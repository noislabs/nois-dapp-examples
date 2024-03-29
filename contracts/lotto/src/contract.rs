use crate::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, LottoResponse, LottosResponse,
    ProtocolBalancesResponse, QueryMsg,
};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    ensure_eq, to_json_binary, Addr, Attribute, BankMsg, Coin, Deps, DepsMut, Empty, Env,
    MessageInfo, Order, QueryResponse, Response, StdResult, Uint128, WasmMsg,
};
use cw2::set_contract_version;
use cw_storage_plus::Bound;
use nois::{NoisCallback, ProxyExecuteMsg};

use crate::error::ContractError;
use crate::state::{Config, Lotto, CONFIG, LOTTOS, PROTOCOL_BALANCES};

const MAX_LOTTO_DURATION: u64 = 2_592_000; // 30 days
const RANDOMNESS_SAFETY_MARGIN: u64 = 5; //in seconds

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // validate address is correct
    let addr = deps
        .api
        .addr_validate(msg.manager.as_str())
        .map_err(|_| ContractError::InvalidAddress {})?;

    let mut allowlisted_recipients: Vec<Addr> = vec![];

    // Verify that all the addresses in recipients_list are valid
    for recipient in msg.recipients_list {
        let recipient_addr = deps.api.addr_validate(&recipient)?;

        allowlisted_recipients.push(recipient_addr);
    }

    let proxy = deps
        .api
        .addr_validate(&msg.nois_proxy)
        .map_err(|_| ContractError::InvalidAddress {})?;
    let protocol_commission_percent = msg.protocol_commission_percent;
    let creator_commission_percent = msg.creator_commission_percent;

    if protocol_commission_percent + creator_commission_percent >= 100 {
        return Err(ContractError::IncorrectRates {});
    }

    let cnfg = Config {
        manager: addr,
        lotto_nonce: 0,
        nois_proxy: proxy,
        allowlisted_recipients,
        protocol_commission_percent,
        creator_commission_percent,
        is_paused: false,
    };

    CONFIG.save(deps.storage, &cnfg)?;

    set_contract_version(
        deps.storage,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    )?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("manager", info.sender))
}

#[cfg_attr(not(feature = "library"), ::cosmwasm_std::entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> StdResult<Response> {
    set_contract_version(
        deps.storage,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    )?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreateLotto {
            ticket_price,
            duration_seconds,
            number_of_winners,
            recipients_list,
        } => execute_create_lotto(
            deps,
            env,
            info,
            ticket_price,
            duration_seconds,
            number_of_winners,
            recipients_list,
        ),
        ExecuteMsg::UpdateAllowlistedRecipients { add, remove } => {
            execute_update_allow_listed_recipients(deps, info, add, remove)
        }
        ExecuteMsg::BuyTicket { lotto_id } => execute_buy_ticket(deps, env, info, lotto_id),
        ExecuteMsg::NoisReceive { callback } => execute_receive(deps, env, info, callback),
        ExecuteMsg::SetConfig {
            nois_proxy,
            manager,
            lotto_nonce,
            recipients_list,
            protocol_commission_percent,
            creator_commission_percent,
            is_paused,
        } => execute_set_config(
            deps,
            info,
            nois_proxy,
            manager,
            lotto_nonce,
            recipients_list,
            protocol_commission_percent,
            creator_commission_percent,
            is_paused,
        ),
        ExecuteMsg::WithdrawAll { address, denom } => {
            execute_withdraw_all(deps, info, address, denom)
        }
    }
}

fn execute_create_lotto(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    ticket_price: Coin,
    duration_seconds: u64,
    number_of_winners: u32,
    recipients_list: Vec<(String, u32)>,
) -> Result<Response, ContractError> {
    // validate Timestamp
    let mut config = CONFIG.load(deps.storage)?;
    let mut nonce = config.lotto_nonce;

    if config.is_paused {
        return Err(ContractError::ContractIsPaused {});
    };

    let mut allowlisted_recipients_total_percentage = 0;
    let mut verified_recipients_list: Vec<(Addr, u32)> = vec![];
    // Verify that all the addresses in recipients_list are valid
    for recipient in recipients_list {
        let recipient_addr = deps.api.addr_validate(&recipient.0)?;
        // Ensure all the addresses in receipient_list are already registered in the contract
        if !config.allowlisted_recipients.contains(&recipient_addr) {
            return Err(ContractError::AddressNotAllowListed {
                addr: recipient_addr.to_string(),
            });
        }
        allowlisted_recipients_total_percentage += recipient.1;
        verified_recipients_list.push((recipient_addr, recipient.1));
    }
    // Verify that the percentages on recipients_list is not greater than 100
    if allowlisted_recipients_total_percentage > 100 {
        return Err(ContractError::IncorrectRates {});
    }

    // Check that duration_seconds is inferior to MAX_LOTTO_DURATION
    if duration_seconds > MAX_LOTTO_DURATION {
        return Err(ContractError::MaxDurationExceeded {
            max_duration: MAX_LOTTO_DURATION,
            desired_duration: duration_seconds,
        });
    }

    let expiration = env.block.time.plus_seconds(duration_seconds);

    let lotto = Lotto {
        nonce,
        ticket_price,
        balance: Uint128::new(0),
        participants: vec![],
        expiration,
        winners: None,
        creator: info.sender,
        number_of_winners,
        recipients_list: verified_recipients_list,
    };

    LOTTOS.save(deps.storage, nonce, &lotto)?;

    let msg = WasmMsg::Execute {
        contract_addr: config.clone().nois_proxy.into_string(),
        // GetRandomnessAfter requests the randomness from the proxy after a specific timestamp
        // The job id is needed to know what randomness we are referring to upon reception in the callback.
        msg: to_json_binary(&ProxyExecuteMsg::GetRandomnessAfter {
            after: expiration.plus_seconds(RANDOMNESS_SAFETY_MARGIN),
            job_id: "lotto-".to_string() + nonce.to_string().as_str(),
        })?,
        // We pay here the proxy contract with whatever the depositors sends. The depositor needs to check in advance the proxy prices.
        funds: info.funds, // Just pass on all funds we got
    };
    nonce += 1;
    config.lotto_nonce = nonce;
    CONFIG.save(deps.storage, &config)?;

    // save config
    Ok(Response::new()
        .add_message(msg)
        .add_attribute("action", "create_lotto")
        .add_attribute("next_nonce", nonce.to_string()))
}

fn validate_payment(deposit: &Coin, funds: &[Coin]) -> Result<(), ContractError> {
    if funds.is_empty() {
        return Err(ContractError::NoFundsProvided);
    }
    // TODO disallow participant to deposit more than one denom

    for fund in funds {
        if deposit == fund {
            return Ok(());
        }
    }
    Err(ContractError::InvalidPayment)
}

#[allow(clippy::too_many_arguments)]
fn execute_set_config(
    deps: DepsMut,
    info: MessageInfo,
    nois_proxy: Option<String>,
    manager: Option<String>,
    lotto_nonce: Option<u64>,
    recipients_list: Option<Vec<String>>,
    protocol_commission_percent: Option<u32>,
    creator_commission_percent: Option<u32>,
    is_paused: Option<bool>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    let mut allowlisted_recipients: Vec<Addr> = vec![];

    if let Some(r) = recipients_list {
        // Verify that all the addresses in recipients_list are valid

        for recipient in r {
            let recipient_addr = deps.api.addr_validate(&recipient)?;

            allowlisted_recipients.push(recipient_addr);
        }
    } else {
        allowlisted_recipients = config.allowlisted_recipients;
    }

    let manager = match manager {
        Some(ma) => deps.api.addr_validate(&ma)?,
        None => config.manager,
    };
    let nois_proxy = match nois_proxy {
        Some(np) => deps.api.addr_validate(&np)?,
        None => config.nois_proxy,
    };

    let lotto_nonce = lotto_nonce.unwrap_or(config.lotto_nonce);
    let protocol_commission_percent =
        protocol_commission_percent.unwrap_or(config.protocol_commission_percent);
    let creator_commission_percent =
        creator_commission_percent.unwrap_or(config.creator_commission_percent);

    let is_paused = is_paused.unwrap_or(config.is_paused);

    // TODO Check that the commissions are less than 100% and that the new values don't mess up with currently running lottos

    let new_config = Config {
        manager,
        nois_proxy,
        lotto_nonce,
        allowlisted_recipients,
        protocol_commission_percent,
        creator_commission_percent,
        is_paused,
    };

    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default().add_attribute("action", "set_config"))
}

fn execute_update_allow_listed_recipients(
    deps: DepsMut,
    info: MessageInfo,
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    let mut updated_allowlist = Vec::new();

    // Add new addresses to the allowlist
    for recipient in add {
        let addr = deps.api.addr_validate(&recipient)?;
        if !config.allowlisted_recipients.contains(&addr) {
            updated_allowlist.push(addr);
        }
    }

    // Remove addresses from the allowlist
    for recipient in &config.allowlisted_recipients {
        let recipient_addr = deps.api.addr_validate(recipient.as_str())?;
        if !remove.contains(&recipient_addr.to_string()) {
            updated_allowlist.push(recipient_addr);
        }
    }

    config.allowlisted_recipients = updated_allowlist;

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default().add_attribute("action", "set_config"))
}

fn execute_buy_ticket(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    lotto_id: u64,
) -> Result<Response, ContractError> {
    if !LOTTOS.has(deps.storage, lotto_id) {
        return Err(ContractError::LottoNotFound {});
    }

    let mut lotto = LOTTOS.load(deps.storage, lotto_id)?;
    let ticket_price = lotto.clone().ticket_price;

    // Not sure the best way to go about validating the coin
    validate_payment(&ticket_price, info.funds.as_slice())?;

    // Check if lotto is active
    if env.block.time >= lotto.expiration {
        return Err(ContractError::LottoDepositStageEnded {});
    }
    // Increment total deposit
    let amount: Uint128 = info
        .funds
        .iter()
        .filter(|coin| coin.denom == ticket_price.denom)
        .map(|coin| coin.amount)
        .sum();

    lotto.balance += amount;
    // Add participant address
    lotto.participants.push(info.sender.clone());

    // Save the state & updated config escrow balance
    LOTTOS.save(deps.storage, lotto_id, &lotto)?;

    Ok(Response::new()
        .add_attribute("action", "participate")
        .add_attribute("sender", info.sender.as_ref())
        .add_attribute("new_balance", lotto.balance.to_string()))
}

pub fn execute_receive(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    callback: NoisCallback,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // callback should only be allowed to be called by the proxy contract
    // otherwise anyone can cut the randomness workflow and cheat the randomness by sending the randomness directly to this contract
    ensure_eq!(
        info.sender,
        config.nois_proxy,
        ContractError::UnauthorizedReceive
    );
    let randomness: [u8; 32] = callback
        .randomness
        .to_array()
        .map_err(|_| ContractError::InvalidRandomness)?;

    // extract lotto nonce
    let job_id = callback.job_id;
    let lotto_nonce: u64 = job_id
        .strip_prefix("lotto-")
        .expect("Strange, how is the job-id not prefixed with lotto-")
        .parse()
        .unwrap(); //Needs to check that the received nonce is a number

    // Make sure the lotto nonce is valid
    let lotto = LOTTOS.load(deps.storage, lotto_nonce)?;
    assert!(lotto.winners.is_none(), "Strange, there's already winners");
    let participants = lotto.participants;

    let winners = nois::pick(
        randomness,
        lotto.number_of_winners as usize,
        participants.clone(),
    );

    if winners.is_empty() {
        return Err(ContractError::NoDepositors {});
    }

    let amount_creator = get_percentage(lotto.balance, config.creator_commission_percent);
    let amount_protocol = get_percentage(lotto.balance, config.protocol_commission_percent);
    let winnable_amount = lotto.balance - amount_creator - amount_protocol;

    let mut recipients_list_amounts: Vec<(Addr, Uint128)> = vec![];
    let mut recipients_list_amounts_total: Uint128 = Uint128::new(0);
    for recipient in lotto.recipients_list.clone() {
        let recipient_amount = get_percentage(winnable_amount, recipient.1);
        recipients_list_amounts.push((recipient.0, recipient_amount));
        recipients_list_amounts_total += recipient_amount;
    }

    let prize_amount = winnable_amount - recipients_list_amounts_total;
    let amount_winner = prize_amount.multiply_ratio(
        Uint128::new(1),
        Uint128::new(lotto.number_of_winners as u128),
    );

    let denom = lotto.ticket_price.clone().denom;

    let mut msgs = vec![
        // creator
        BankMsg::Send {
            to_address: lotto.creator.clone().into_string(),
            amount: vec![Coin {
                amount: amount_creator,
                denom: denom.clone(),
            }],
        },
    ];
    for allowlisted_recipient in recipients_list_amounts {
        msgs.push(
            // allowlisted recipient
            BankMsg::Send {
                to_address: allowlisted_recipient.0.into_string(),
                amount: vec![Coin {
                    amount: allowlisted_recipient.1,
                    denom: denom.clone(),
                }],
            },
        );
    }
    for winner in winners.clone() {
        msgs.push(
            // Winner
            BankMsg::Send {
                to_address: winner.clone().into_string(),
                amount: vec![Coin {
                    amount: amount_winner,
                    denom: denom.clone(),
                }],
            },
        );
    }

    // Update Lotto Data
    let new_lotto = Lotto {
        nonce: lotto_nonce,
        ticket_price: lotto.ticket_price,
        balance: lotto.balance,
        expiration: lotto.expiration,
        participants,
        winners: Some(winners.clone()),
        creator: lotto.creator,
        number_of_winners: lotto.number_of_winners,
        recipients_list: lotto.recipients_list,
    };

    // Increment protocol amount
    let protocol_balances = PROTOCOL_BALANCES.may_load(deps.storage, denom.clone())?;
    match protocol_balances {
        Some(pb) => PROTOCOL_BALANCES.save(deps.storage, denom.clone(), &(pb + amount_protocol))?,
        None => PROTOCOL_BALANCES.save(deps.storage, denom.clone(), &amount_protocol)?,
    };

    LOTTOS.save(deps.storage, lotto_nonce, &new_lotto)?;

    // msgs.push(CosmosMsg::Stargate {
    //     type_url: "/cosmos.distribution.v1beta1.MsgFundCommunityPool".to_string(),
    //     value: encode_msg_fund_community_pool(
    //         &Coin {
    //             denom: denom.clone(),
    //             amount: amount_community_pool,
    //         },
    //         &env.contract.address,
    //     )
    //     .into(),
    // });

    Ok(Response::new().add_messages(msgs).add_attributes(vec![
        Attribute::new("action", "receive-randomness-and-send-prize"),
        Attribute::new("job_id", job_id),
        Attribute::new(
            "winner_send_amount",
            Coin {
                amount: amount_winner,
                denom,
            }
            .to_string(),
        ), // actual send amount
    ]))
}

fn get_percentage(amount: Uint128, ratio: u32) -> Uint128 {
    amount.mul_floor((ratio as u128, 100))
}

fn execute_withdraw_all(
    deps: DepsMut,
    info: MessageInfo,
    to_address: String,
    denom: String,
) -> Result<Response, ContractError> {
    // TODO CRITICAL! Make sure not to withdraw current deposits that have not been settled
    // Keep a state of the manager revenue

    let config = CONFIG.load(deps.storage)?;

    // check the calling address is the authorised address
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    let payable_amount: Uint128;

    let protocol_balance = PROTOCOL_BALANCES.may_load(deps.storage, denom.clone())?;
    if let Some(pb) = protocol_balance {
        payable_amount = pb;
    } else {
        return Err(ContractError::ProtocolBalanceDoesNotOwnSuchDenom {
            denom: denom.clone(),
        });
    };

    let payable_balance: Coin = Coin::new(u128::from(payable_amount), denom.clone());
    PROTOCOL_BALANCES.save(deps.storage, denom.clone(), &Uint128::zero())?;

    let msg = BankMsg::Send {
        to_address,
        amount: vec![payable_balance.clone()],
    };

    let res = Response::new()
        .add_message(msg)
        .add_attribute("action", "withdraw_all")
        .add_attribute("amount", payable_balance.to_string());
    Ok(res)
}

// For chains that have a community pool module, you can use this function.
// Neutron has a community pool built as a cosmwasm contract
// fn encode_msg_fund_community_pool(amount: &Coin, depositor: &Addr) -> Vec<u8> {
//     // Coin: https://github.com/cosmos/cosmos-sdk/blob/v0.45.15/proto/cosmos/base/v1beta1/coin.proto#L14-L19
//     // MsgFundCommunityPool: https://github.com/cosmos/cosmos-sdk/blob/v0.45.15/proto/cosmos/distribution/v1beta1/tx.proto#L69-L76
//     let coin = Anybuf::new()
//         .append_string(1, &amount.denom)
//         .append_string(2, amount.amount.to_string());
//     Anybuf::new()
//         .append_message(1, &coin)
//         .append_string(2, depositor)
//         .into_vec()
// }

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    let response = match msg {
        QueryMsg::Lotto { lotto_nonce } => to_json_binary(&query_lotto(deps, env, lotto_nonce)?)?,
        QueryMsg::ProtocolBalances {} => to_json_binary(&query_protocol_balances(deps)?)?,
        QueryMsg::LottosDesc {
            creator,
            is_active,
            start_after,
            limit,
        } => to_json_binary(&query_lottos(
            deps,
            env,
            creator,
            is_active,
            start_after,
            limit,
            Order::Descending,
        )?)?,
        QueryMsg::LottosAsc {
            creator,
            is_active,
            start_after,
            limit,
        } => to_json_binary(&query_lottos(
            deps,
            env,
            creator,
            is_active,
            start_after,
            limit,
            Order::Ascending,
        )?)?,
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?)?,
    };
    Ok(response)
}

fn query_lotto(deps: Deps, env: Env, nonce: u64) -> StdResult<LottoResponse> {
    let lotto = LOTTOS.load(deps.storage, nonce)?;
    let winners = lotto
        .winners
        .map(|winners| winners.iter().map(|wn| wn.clone().into_string()).collect());
    let is_expired = env.block.time > lotto.expiration;
    Ok(LottoResponse {
        nonce: lotto.nonce,
        ticket_price: lotto.ticket_price,
        balance: lotto.balance,
        participants: lotto
            .participants
            .iter()
            .map(|dep| dep.to_string())
            .collect(),
        winners,
        is_expired,
        expiration: lotto.expiration,
        creator: lotto.creator.to_string(),
        number_of_winners: lotto.number_of_winners,
        recipients_list: lotto
            .recipients_list
            .into_iter()
            .map(|r| (r.0.to_string(), r.1))
            .collect(),
    })
}

fn query_lottos(
    deps: Deps,
    env: Env,
    creator: Option<String>,
    is_active: Option<bool>,
    start_after: Option<u64>,
    limit: Option<u64>,
    order: Order,
) -> StdResult<LottosResponse> {
    let limit: usize = limit.unwrap_or(100) as usize;
    let (low_bound, top_bound) = match order {
        Order::Ascending => (start_after.map(Bound::exclusive), None),
        Order::Descending => (None, start_after.map(Bound::exclusive)),
    };
    let lottos: Vec<LottoResponse> = LOTTOS
        .range(deps.storage, low_bound, top_bound, order)
        .filter(|l| {
            if let Some(creator) = &creator {
                l.as_ref().unwrap().1.creator.as_ref() == creator
            } else {
                true
            }
        })
        .filter(|l| {
            if let Some(is_active) = &is_active {
                (l.as_ref().unwrap().1.expiration > env.block.time) == *is_active
            } else {
                true
            }
        })
        .take(limit)
        .map(|c| {
            c.map(|(nonce, lotto)| {
                let winners = lotto
                    .winners
                    .map(|winners| winners.iter().map(|wn| wn.clone().into_string()).collect());

                LottoResponse {
                    ticket_price: lotto.ticket_price,
                    balance: lotto.balance,
                    participants: lotto
                        .participants
                        .iter()
                        .map(|dep| dep.to_string())
                        .collect(),
                    expiration: lotto.expiration,
                    winners,
                    nonce,
                    creator: lotto.creator.to_string(),
                    number_of_winners: lotto.number_of_winners,
                    recipients_list: lotto
                        .recipients_list
                        .into_iter()
                        .map(|r| (r.0.to_string(), r.1))
                        .collect(),
                    is_expired: env.block.time > lotto.expiration,
                }
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(LottosResponse { lottos })
}

fn query_protocol_balances(deps: Deps) -> StdResult<ProtocolBalancesResponse> {
    let balances = PROTOCOL_BALANCES
        .range(deps.storage, None, None, Order::Ascending)
        .map(|balance| Coin {
            denom: balance.as_ref().unwrap().clone().0,
            amount: balance.unwrap().1,
        })
        .collect();
    Ok(ProtocolBalancesResponse { balances })
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        manager: config.manager.to_string(),
        nois_proxy: config.nois_proxy.to_string(),
        is_paused: config.is_paused,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Empty, HexBinary, OwnedDeps, SubMsg, Timestamp};

    const CREATOR: &str = "creator1";
    const PROXY_ADDRESS: &str = "the proxy of choice";
    const MANAGER: &str = "manager";

    fn instantiate_contract() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let allowlisted_recipients =
            vec!["community_pool".to_string(), "public_funding_1".to_string()];
        let msg = InstantiateMsg {
            manager: MANAGER.to_string(),
            nois_proxy: PROXY_ADDRESS.to_string(),
            recipients_list: allowlisted_recipients,
            protocol_commission_percent: 5,
            creator_commission_percent: 15,
        };

        let info = mock_info(CREATOR, &[]);
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        deps
    }

    #[test]
    fn proper_instantiation() {
        let deps = instantiate_contract();
        let env = mock_env();

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(res).unwrap();
        assert_eq!(MANAGER, config.manager.as_str());
    }

    #[test]
    fn query_lottos_works() {
        let mut deps = instantiate_contract();
        let env = mock_env();
        // Create few lottos
        // lotto-0
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        // lotto-1
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        // lotto-2
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // lotto-3
        let info = mock_info("creator-2", &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        // lotto-4
        let info = mock_info("creator-2", &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Query CREATOR ASC
        let LottosResponse { lottos } = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::LottosAsc {
                    creator: Some(CREATOR.to_string()),
                    is_active: Some(true),
                    start_after: None,
                    limit: Some(10),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let response_lotto_nonces = lottos.iter().map(|b| b.nonce).collect::<Vec<u64>>();
        assert_eq!(response_lotto_nonces, [0, 1, 2]);
        // Query creator-2 desc
        let LottosResponse { lottos } = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::LottosDesc {
                    creator: Some("creator-2".to_string()),
                    is_active: Some(true),
                    start_after: None,
                    limit: Some(10),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let response_lotto_nonces = lottos.iter().map(|b| b.nonce).collect::<Vec<u64>>();
        assert_eq!(response_lotto_nonces, [4, 3]);
        // Query all creators desc
        let LottosResponse { lottos } = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::LottosDesc {
                    creator: None,
                    is_active: Some(true),
                    start_after: None,
                    limit: Some(10),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let response_lotto_nonces = lottos.iter().map(|b| b.nonce).collect::<Vec<u64>>();
        assert_eq!(response_lotto_nonces, [4, 3, 2, 1, 0]);
        // Query all creators desc with limit 2
        let LottosResponse { lottos } = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::LottosDesc {
                    creator: None,
                    is_active: Some(true),
                    start_after: None,
                    limit: Some(2),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let response_lotto_nonces = lottos.iter().map(|b| b.nonce).collect::<Vec<u64>>();
        assert_eq!(response_lotto_nonces, [4, 3]);
        // Query all inactive lottos
        let LottosResponse { lottos } = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::LottosDesc {
                    creator: None,
                    is_active: Some(false),
                    start_after: None,
                    limit: Some(2),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let response_lotto_nonces = lottos.iter().map(|b| b.nonce).collect::<Vec<u64>>();
        assert_eq!(response_lotto_nonces, [] as [u64; 0]);
    }
    #[test]
    fn lotto_works() {
        let mut deps = instantiate_contract();
        let env = mock_env();

        // creator creates a lotto instance with a non allowlisted recipient
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![(CREATOR.to_string(), 20)],
        };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::AddressNotAllowListed {
                addr: CREATOR.to_string()
            }
        );

        // creator creates a lotto instance with more than 100% total recipients
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![
                ("community_pool".to_string(), 20),
                ("public_funding_1".to_string(), 90),
            ],
        };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::IncorrectRates);

        // creator creates a lotto instance
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // manager sets the contract to be paused
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::SetConfig {
            nois_proxy: None,
            manager: None,
            lotto_nonce: None,
            recipients_list: None,
            protocol_commission_percent: None,
            creator_commission_percent: None,
            is_paused: Some(true),
        };
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // creator creates a second lotto instance after the contract was paused
        let info = mock_info(CREATOR, &[]);
        let msg = ExecuteMsg::CreateLotto {
            ticket_price: Coin {
                denom: "untrn".to_string(),
                amount: Uint128::new(100_000_000),
            },
            duration_seconds: 90,
            number_of_winners: 2,
            recipients_list: vec![("community_pool".to_string(), 20)],
        };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::ContractIsPaused);

        // someone deposits wrong amount
        let info = mock_info(
            "participant-1",
            &[Coin::new(50_000_000, "untrn".to_string())],
        );
        let msg = ExecuteMsg::BuyTicket { lotto_id: 0 };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::InvalidPayment {});
        // someone deposits for inexistant lotto
        let info = mock_info(
            "participant-1",
            &[Coin::new(50_000_000, "untrn".to_string())],
        );
        let msg = ExecuteMsg::BuyTicket { lotto_id: 1 };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::LottoNotFound {});

        // someone deposits correctly
        let msg = ExecuteMsg::BuyTicket { lotto_id: 0 };
        let info = mock_info(
            "participant-1",
            &[Coin::new(100_000_000, "untrn".to_string())],
        );
        execute(deps.as_mut(), env.clone(), info, msg.clone()).unwrap();
        let info = mock_info(
            "participant-2",
            &[Coin::new(100_000_000, "untrn".to_string())],
        );
        execute(deps.as_mut(), env.clone(), info, msg.clone()).unwrap();
        let info = mock_info(
            "participant-3",
            &[Coin::new(100_000_000, "untrn".to_string())],
        );
        execute(deps.as_mut(), env.clone(), info, msg.clone()).unwrap();
        let info = mock_info(
            "participant-4",
            &[Coin::new(100_000_000, "untrn".to_string())],
        );
        execute(deps.as_mut(), env.clone(), info, msg.clone()).unwrap();
        let info = mock_info(
            "participant-5",
            &[Coin::new(100_000_000, "untrn".to_string())],
        );
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Receive randomness
        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "lotto-0".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa115",
                )
                .unwrap(),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                Attribute::new("action", "receive-randomness-and-send-prize"),
                Attribute::new("job_id", "lotto-0"),
                Attribute::new("winner_send_amount", "160000000untrn"),
            ]
        );
        let expected = vec![
            SubMsg::new(BankMsg::Send {
                to_address: "creator1".to_string(),
                amount: vec![Coin {
                    amount: Uint128::new(75_000000),
                    denom: "untrn".to_string(),
                }],
            }),
            SubMsg::new(BankMsg::Send {
                to_address: "community_pool".to_string(),
                amount: vec![Coin {
                    amount: Uint128::new(80_000000),
                    denom: "untrn".to_string(),
                }],
            }),
            SubMsg::new(BankMsg::Send {
                to_address: "participant-4".to_string(),
                amount: vec![Coin {
                    amount: Uint128::new(160_000000),
                    denom: "untrn".to_string(),
                }],
            }),
            SubMsg::new(BankMsg::Send {
                to_address: "participant-5".to_string(),
                amount: vec![Coin {
                    amount: Uint128::new(160_000000),
                    denom: "untrn".to_string(),
                }],
            }),
        ];
        assert_eq!(res.messages, expected);

        // Query protocol balances
        let ProtocolBalancesResponse { balances } =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::ProtocolBalances {}).unwrap())
                .unwrap();
        //let response_balances: Vec<Coin> = balances.iter().map(|b| b).collect();
        assert_eq!(balances, vec![Coin::new(25000000, "untrn".to_string())]);

        // someone tries to withdraw smart contract funds
        let info = mock_info("someone", &[]);
        let msg = ExecuteMsg::WithdrawAll {
            address: "someone".to_string(),
            denom: "untrn".to_string(),
        };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // manager tries to withdraw BTC funds
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::WithdrawAll {
            address: "manager_second_address".to_string(),
            denom: "btc".to_string(),
        };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::ProtocolBalanceDoesNotOwnSuchDenom {
                denom: "btc".to_string()
            }
        );

        // manager tries to withdraw smart contract funds
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::WithdrawAll {
            address: "manager_second_address".to_string(),
            denom: "untrn".to_string(),
        };
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                Attribute::new("action", "withdraw_all"),
                Attribute::new("amount", "25000000untrn"),
            ]
        );
        let expected = vec![SubMsg::new(BankMsg::Send {
            to_address: "manager_second_address".to_string(),
            amount: vec![Coin {
                amount: Uint128::new(25000000),
                denom: "untrn".to_string(),
            }],
        })];
        assert_eq!(res.messages, expected);

        // TODO test  with multiple allowlisted recipients
    }
}
