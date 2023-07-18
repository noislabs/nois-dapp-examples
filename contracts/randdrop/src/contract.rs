use cosmwasm_std::{
    ensure_eq, entry_point, to_binary, Addr, Attribute, BankMsg, Coin, CosmosMsg, Deps, DepsMut,
    Env, HexBinary, MessageInfo, Order, QueryResponse, Response, StdResult, Uint128, WasmMsg,
};
use nois::{NoisCallback, ProxyExecuteMsg};
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, IsWinnerResponse, ParticipantDataResponse,
    ParticipantResponse, QueryMsg, ResultsResponse,
};
use crate::state::{Config, NoisProxy, ParticipantData, CONFIG, PARTICIPANTS};

/// The winning chance is 1/AIRDROP_ODDS
const AIRDROP_ODDS: u64 = 3;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let manager = deps
        .api
        .addr_validate(&msg.manager)
        .map_err(|_| ContractError::InvalidManagerAddress)?;
    let randdrop_denom = msg.randdrop_denom;
    let nois_proxy_address = deps
        .api
        .addr_validate(&msg.nois_proxy_address)
        .map_err(|_| ContractError::InvalidProxyAddress)?;
    let nois_proxy_price = Coin {
        denom: msg.nois_proxy_denom,
        amount: msg.nois_proxy_amount,
    };
    let nois_proxy = NoisProxy {
        address: nois_proxy_address,
        price: nois_proxy_price,
    };
    let merkle_root = msg.merkle_root;
    if merkle_root.len() != 32 {
        return Err(ContractError::WrongMerkleRootLength {});
    }

    let config = Config {
        manager,
        randdrop_denom,
        nois_proxy,
        merkle_root,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::UpdateConfig {
            manager,
            nois_proxy_denom,
            nois_proxy_amount,
            nois_proxy_address,
            randdrop_denom,
            merkle_root,
        } => execute_update_config(
            deps,
            env,
            info,
            manager,
            randdrop_denom,
            nois_proxy_denom,
            nois_proxy_amount,
            nois_proxy_address,
            merkle_root,
        ),
        // Randdrop should be called by an eligable user to start the process
        ExecuteMsg::Participate { amount, proof } => {
            execute_participate(deps, env, info, amount, proof)
        }
        // NoisReceive should be called by the proxy contract. The proxy is forwarding the randomness from the nois chain to this contract.
        ExecuteMsg::NoisReceive { callback } => execute_receive(deps, env, info, callback),
        ExecuteMsg::WithdrawAll { address } => execute_withdraw_all(deps, env, info, address),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    let response = match msg {
        QueryMsg::IsWinner { address } => to_binary(&query_is_winner(deps, address)?)?,
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
        QueryMsg::RanddropResults {} => to_binary(&query_results(deps)?)?,
        QueryMsg::Participant { address } => to_binary(&query_participant(deps, address)?)?,
    };
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    manager: Option<String>,
    randdrop_denom: Option<String>,
    nois_proxy_denom: Option<String>,
    nois_proxy_amount: Option<Uint128>,
    nois_proxy_address: Option<String>,
    merkle_root: Option<HexBinary>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    // check the calling address is the authorised multisig
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    let manager = match manager {
        Some(ma) => deps.api.addr_validate(&ma)?,
        None => config.manager,
    };
    let randdrop_denom = randdrop_denom.unwrap_or(config.randdrop_denom);
    let nois_proxy_denom = nois_proxy_denom.unwrap_or(config.nois_proxy.price.denom);
    let nois_proxy_amount = nois_proxy_amount.unwrap_or(config.nois_proxy.price.amount);
    let nois_proxy_address = match nois_proxy_address {
        Some(np) => deps.api.addr_validate(&np)?,
        None => config.nois_proxy.address,
    };

    let merkle_root = match merkle_root {
        Some(mr) => {
            if mr.len() != 32 {
                return Err(ContractError::WrongMerkleRootLength {});
            }
            mr
        }
        None => config.merkle_root,
    };

    let nois_proxy = NoisProxy {
        price: Coin {
            denom: nois_proxy_denom,
            amount: nois_proxy_amount,
        },
        address: nois_proxy_address,
    };

    CONFIG.save(
        deps.storage,
        &Config {
            manager,
            randdrop_denom,
            nois_proxy,
            merkle_root,
        },
    )?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

// This function will call the proxy and ask for the randomness round
pub fn execute_participate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
    proof: Vec<HexBinary>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    if PARTICIPANTS.has(deps.storage, &info.sender) {
        return Err(ContractError::UserAlreadyParticipated);
    }

    // The contract will spend NOIS tokens on this info.sender to buy randomness.
    // To prevent spam and users abusing the funds, we only allow addresses listed on the randdrop to call this entrypoint
    // Sending the proof here will make sure that the sender is a potential randdrop winner
    if !is_proof_valid(&info.sender, amount, config.merkle_root, proof)? {
        return Err(ContractError::InvalidProof {});
    }

    // Get the price from the nois-proxy

    let response = Response::new().add_message(WasmMsg::Execute {
        contract_addr: config.nois_proxy.address.into_string(),
        // GetNextRandomness requests the randomness from the proxy
        // The job id is needed to know what randomness we are referring to upon reception in the callback.
        msg: to_binary(&ProxyExecuteMsg::GetNextRandomness {
            job_id: "randdrop-".to_string() + info.sender.as_str(),
        })?,

        funds: vec![config.nois_proxy.price], // Pay from the contract
    });

    // Register randdrop participant
    let participant_data = &ParticipantData {
        randomness: None,
        base_randdrop_amount: amount,
        winning_amount: None,
        participate_time: env.block.time,
        claim_time: None,
    };
    PARTICIPANTS.save(deps.storage, &info.sender, participant_data)?;

    Ok(response)
}

pub fn execute_receive(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    callback: NoisCallback,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // callback should only be allowed to be called by the proxy contract
    // otherwise anyone can cut the randomness workflow and cheat the randomness by sending the randomness directly to this contract
    ensure_eq!(
        info.sender,
        config.nois_proxy.address,
        ContractError::UnauthorizedReceive
    );
    let randomness: [u8; 32] = callback
        .randomness
        .to_array()
        .map_err(|_| ContractError::InvalidRandomness)?;

    // extract participant address
    let job_id = callback.job_id;
    let participant_address = job_id
        .strip_prefix("randdrop-")
        .expect("Strange, how is the job-id not prefixed with randdrop-");
    let participant_address = deps.api.addr_validate(participant_address)?;

    // Make sure the participant is registered
    let participant_data = PARTICIPANTS.load(deps.storage, &participant_address)?;
    assert!(
        participant_data.randomness.is_none(),
        "Strange, participant's randomness already received"
    );
    assert!(
        participant_data.winning_amount.is_none(),
        "Strange, participant's winning_amount is already set"
    );
    let mut msgs = Vec::<CosmosMsg>::new();

    let winning_amount = if is_randdrop_winner(&participant_address, randomness) {
        let randdrop_amount = participant_data.base_randdrop_amount * Uint128::from(AIRDROP_ODDS);
        msgs.push(
            BankMsg::Send {
                to_address: participant_address.to_string(),
                amount: vec![Coin {
                    amount: randdrop_amount,
                    denom: config.randdrop_denom.clone(),
                }],
            }
            .into(),
        );
        randdrop_amount
    } else {
        Uint128::zero()
    };

    // Update Participant Data
    let new_participant_data = ParticipantData {
        randomness: Some(randomness.into()),
        winning_amount: Some(winning_amount),
        base_randdrop_amount: participant_data.base_randdrop_amount,
        claim_time: Some(env.block.time),
        participate_time: participant_data.participate_time,
    };
    PARTICIPANTS.save(deps.storage, &participant_address, &new_participant_data)?;

    Ok(Response::new().add_messages(msgs).add_attributes(vec![
        Attribute::new("action", "receive-randomness-and-send-randdrop"),
        Attribute::new("address", info.sender),
        Attribute::new("job_id", job_id),
        Attribute::new("participant", participant_address),
        Attribute::new("is_winner", (!winning_amount.is_zero()).to_string()),
        Attribute::new("merkle_amount", participant_data.base_randdrop_amount), // value from the merkle tree
        Attribute::new(
            "winning_amount",
            Coin {
                amount: winning_amount,
                denom: config.randdrop_denom,
            }
            .to_string(),
        ), // actual sent amount
    ]))
}

fn execute_withdraw_all(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    address: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    // check the calling address is the authorised address
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    let mut out_msgs = Vec::<BankMsg>::new();

    let amount = deps
        .querier
        .query_balance(env.contract.address.clone(), config.randdrop_denom.clone())?;
    let msg = BankMsg::Send {
        to_address: address.clone(),
        amount: vec![amount],
    };
    out_msgs.push(msg);
    // If the tokens to pay the proxy are different from the randropped tokens then withdraw those as well
    if config.randdrop_denom != config.nois_proxy.price.denom {
        let amount = deps
            .querier
            .query_balance(env.contract.address, config.nois_proxy.price.denom)?;
        let msg = BankMsg::Send {
            to_address: address,
            amount: vec![amount],
        };
        out_msgs.push(msg);
    }

    let res = Response::new()
        .add_messages(out_msgs)
        .add_attribute("action", "withdraw_all");
    Ok(res)
}

fn is_randdrop_winner(participant: &Addr, randomness: [u8; 32]) -> bool {
    // Hash the combined value using SHA256 to generate a random number between 1 and 3
    let mut hasher = Sha256::new();
    // Concatenate the randomness and sender hash values
    hasher.update(randomness);
    hasher.update(participant.as_bytes());
    let hash = hasher.finalize();

    // The u64 range is large compared to the modulo, so the distribution is expected to be good enough.
    // See https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
    let hash_u64 = u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);
    // returns true iff the address is eligible
    hash_u64 % AIRDROP_ODDS == 0
}

fn is_proof_valid(
    address: &Addr,
    amount: Uint128,
    merkle_root: HexBinary,
    proof: Vec<HexBinary>,
) -> Result<bool, ContractError> {
    // "nois1blabla...chksum4500000" -> hash
    let user_input = format!("{}{}", address, amount);
    let hash = sha2::Sha256::digest(user_input.as_bytes()).into();

    // hash all the way up the merkle tree until reaching the top root.
    let hash = proof
        .into_iter()
        .try_fold(hash, |hash, p| -> Result<_, ContractError> {
            let proof_buf: [u8; 32] = p.to_array()?;
            let mut hashes = [hash, proof_buf];
            hashes.sort_unstable();
            Ok(sha2::Sha256::digest(hashes.concat()).into())
        })?;

    // Check the overall cumulated proof hashes along the merkle tree ended up having the same hash as the registered Merkle root
    Ok(merkle_root == hash)
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        manager: config.manager.into(),
        nois_proxy_address: config.nois_proxy.address.into(),
        nois_proxy_denom: config.nois_proxy.price.denom,
        nois_proxy_amount: config.nois_proxy.price.amount,
        randdrop_denom: config.randdrop_denom,
        merkle_root: config.merkle_root,
    })
}

fn query_results(deps: Deps) -> StdResult<ResultsResponse> {
    // No pagination here yet 🤷‍♂️
    // This could fail when many people have participated because we might run out of gas.
    let results = PARTICIPANTS
        .range(deps.storage, None, None, Order::Ascending)
        .map(|participant| participant.unwrap())
        .filter(|participant| participant.1.winning_amount.is_some())
        .map(|(address, paticipant_data)| {
            (
                address.into_string(),
                paticipant_data.winning_amount.unwrap(),
            )
        })
        .collect();
    Ok(ResultsResponse { results })
}

fn query_is_winner(deps: Deps, address: String) -> StdResult<IsWinnerResponse> {
    let address = deps.api.addr_validate(address.as_str())?;
    // Check if the address is lucky to be randomly selected for the randdrop
    let is_winner = match PARTICIPANTS.may_load(deps.storage, &address)? {
        Some(pd) => pd
            .winning_amount
            .map(|winning_amount| !winning_amount.is_zero()),
        None => None,
    };
    Ok(IsWinnerResponse { is_winner })
}

fn query_participant(deps: Deps, address: String) -> StdResult<ParticipantResponse> {
    let address = deps.api.addr_validate(&address)?;
    let participant = PARTICIPANTS.may_load(deps.storage, &address)?;
    let resp = match participant {
        Some(prt) => ParticipantResponse {
            participant: Some(ParticipantDataResponse {
                base_randdrop_amount: prt.base_randdrop_amount,
                randomness: prt.randomness,
                randdrop_duration: if let Some(claim_time) = prt.claim_time {
                    Some(claim_time.seconds() - prt.participate_time.seconds())
                } else {
                    None
                },
                is_winner: prt.winning_amount.map(|wa| !wa.is_zero()),
                winning_amount: prt.winning_amount,
                participate_time: prt.participate_time,
                claim_time: if prt.claim_time.is_some() {
                    Some(prt.claim_time.unwrap())
                } else {
                    None
                },
            }),
        },

        None => ParticipantResponse { participant: None },
    };

    Ok(resp)
}

#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        from_binary, from_slice, Empty, HexBinary, OwnedDeps, StdError, SubMsg, Timestamp,
    };
    use serde::Deserialize;

    const CREATOR: &str = "creator";
    const PROXY_ADDRESS: &str = "the proxy of choice";
    const MANAGER: &str = "manager1";
    const MERKLE_ROOT: &str = "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37";

    fn instantiate_contract(
        merkle_root: HexBinary,
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            manager: MANAGER.to_string(),
            nois_proxy_address: PROXY_ADDRESS.to_string(),
            nois_proxy_amount: Uint128::new(50_000_000),
            nois_proxy_denom:
                "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50".to_string(),
            randdrop_denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                .to_string(),
            merkle_root,
        };

        let info = mock_info(CREATOR, &[]);
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        deps
    }

    #[test]
    fn proper_instantiation() {
        let merkle_root = HexBinary::from_hex(MERKLE_ROOT).unwrap();
        let deps = instantiate_contract(merkle_root);
        let env = mock_env();

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(MANAGER, config.manager.as_str());
    }
    #[test]
    fn instantiate_fails_for_invalid_input() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            manager: MANAGER.to_string(),
            nois_proxy_address: "".to_string(),
            nois_proxy_amount: Uint128::new(50_000_000),
            nois_proxy_denom:
                "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50".to_string(),
            randdrop_denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                .to_string(),
            merkle_root: HexBinary::from_hex(
                "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37",
            )
            .unwrap(),
        };
        let info = mock_info("CREATOR", &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(res, ContractError::InvalidProxyAddress);
    }

    #[test]
    fn update_config() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            manager: MANAGER.to_string(),
            nois_proxy_address: "nois_proxy".to_string(),
            nois_proxy_amount: Uint128::new(50_000_000),
            nois_proxy_denom:
                "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50".to_string(),
            randdrop_denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                .to_string(),
            merkle_root: HexBinary::from_hex(
                "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37",
            )
            .unwrap(),
        };

        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // update manager
        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::UpdateConfig {
            manager: Some("manager2".to_string()),
            nois_proxy_address: None,
            nois_proxy_amount: None,
            nois_proxy_denom: None,
            randdrop_denom: Some("Bitcoin".to_string()),
            merkle_root: Some(
                HexBinary::from_hex(
                    "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d38",
                )
                .unwrap(),
            ),
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!("manager2", config.manager.as_str());

        // Unauthorized err
        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::UpdateConfig {
            manager: None,
            nois_proxy_address: None,
            nois_proxy_amount: None,
            nois_proxy_denom: None,
            randdrop_denom: Some("Bitcoin".to_string()),
            merkle_root: Some(
                HexBinary::from_hex(
                    "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d38",
                )
                .unwrap(),
            ),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});
    }

    const TEST_DATA_WINNER: &[u8] = include_bytes!("../tests/winner.json");
    const TEST_DATA_LOSER: &[u8] = include_bytes!("../tests/loser.json");

    #[derive(Deserialize, Debug)]
    struct Encoded {
        account: String,
        amount: Uint128,
        root: HexBinary,
        proof: Vec<HexBinary>,
    }

    #[test]
    fn participate_in_randdrop_and_claim_process_works() {
        let test_data_winner: Encoded = from_slice(TEST_DATA_WINNER).unwrap();
        let test_data_loser: Encoded = from_slice(TEST_DATA_LOSER).unwrap();
        let mut deps = instantiate_contract(test_data_winner.root);

        let env = mock_env();

        // Someone not from the randdrop list tries to participate
        let info = mock_info("Some-random-person-not-on-the-list", &[]);
        let msg = ExecuteMsg::Participate {
            amount: Uint128::new(4500000),
            proof: test_data_winner.proof.clone(),
        };
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::InvalidProof);
        // Someone from the list trying to fake the amount they should get
        let info = mock_info("nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve", &[]);
        let msg = ExecuteMsg::Participate {
            amount: Uint128::new(14500000),
            proof: test_data_winner.proof.clone(),
        };
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::InvalidProof {});
        // Correct account with correct amount and proof
        let info = mock_info(test_data_winner.account.as_str(), &[]);
        let msg = ExecuteMsg::Participate {
            amount: test_data_winner.amount,
            proof: test_data_winner.proof.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Receive randomness
        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "randdrop-nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa129",
                )
                .unwrap(),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                Attribute::new("action", "receive-randomness-and-send-randdrop"),
                Attribute::new("address", "the proxy of choice"),
                Attribute::new(
                    "job_id",
                    "randdrop-nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve"
                ),
                Attribute::new("participant", "nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve"),
                Attribute::new("is_winner", true.to_string()),
                Attribute::new("merkle_amount", 4500000.to_string()),
                Attribute::new(
                    "winning_amount",
                    "13500000ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                        .to_string()
                ),
            ]
        );
        let expected = SubMsg::new(BankMsg::Send {
            to_address: "nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve".to_string(),
            amount: vec![Coin {
                amount: Uint128::new(13500000), // 4500000*3
                denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                    .to_string(),
            }],
        });
        assert_eq!(res.messages, vec![expected]);

        // Once the randomness came in, is_winner is set to Some
        assert_eq!(
            from_binary::<IsWinnerResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::IsWinner {
                        address: test_data_winner.account.clone()
                    }
                )
                .unwrap()
            )
            .unwrap()
            .is_winner,
            Some(true)
        );

        // Loser's turn
        // Loser fears losing so tries not to play and somehow get the proxy to send some randomness on his behalf
        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "randdrop-nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa129",
                )
                .unwrap(),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        // Should fail because loser did not request randomness yet
        assert_eq!(
            StdError::NotFound {
                kind: "randdrop::state::ParticipantData".to_string()
            }
            .to_string(),
            err.to_string(),
        );
        // Loser decides to play
        // Correct account with correct amount and proof
        let info = mock_info(test_data_loser.account.as_str(), &[]);
        let msg = ExecuteMsg::Participate {
            amount: test_data_loser.amount,
            proof: test_data_loser.proof.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        // Check  loser (didnt lose yet) data before receiving the randomness.
        assert_eq!(
            from_binary::<ParticipantResponse>(
                &query(
                    deps.as_ref(),
                    env,
                    QueryMsg::Participant {
                        address: "nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs".to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            ParticipantResponse {
                participant: Some(ParticipantDataResponse {
                    randomness: None,
                    base_randdrop_amount: Uint128::new(5869),
                    is_winner: None,
                    winning_amount: None,
                    participate_time: Timestamp::from_nanos(1571797419879305533),
                    claim_time: None,
                    randdrop_duration: None,
                })
            }
        );

        // Receive randomness
        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "randdrop-nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa129",
                )
                .unwrap(),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        let mut env = mock_env();
        env.block.time = env.block.time.plus_nanos(45_111_222_333);
        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages, vec![]);
        assert_eq!(
            res.attributes,
            vec![
                Attribute::new("action", "receive-randomness-and-send-randdrop"),
                Attribute::new("address", "the proxy of choice"),
                Attribute::new(
                    "job_id",
                    "randdrop-nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs"
                ),
                Attribute::new("participant", "nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs"),
                Attribute::new("is_winner", false.to_string()),
                Attribute::new("merkle_amount", 5869.to_string()),
                Attribute::new(
                    "winning_amount",
                    "0ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                        .to_string()
                ),
            ]
        );

        // Once the randomness came in, is_winner is set to Some
        assert_eq!(
            from_binary::<IsWinnerResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsWinner {
                        address: test_data_loser.account.clone()
                    }
                )
                .unwrap()
            )
            .unwrap()
            .is_winner,
            Some(false)
        );

        // Stop aridrop and Widhdraw funds
        let env = mock_env();
        let info = mock_info("random_person_who_hates_airdrops", &[]);
        let msg = ExecuteMsg::WithdrawAll {
            address: "some-address".to_string(),
        };
        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::WithdrawAll {
            address: "withdraw_address".to_string(),
        };
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let expected = SubMsg::new(BankMsg::Send {
            to_address: "withdraw_address".to_string(),
            amount: vec![Coin {
                amount: Uint128::new(0),
                denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                    .to_string(),
            }],
        });
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            from_binary::<ResultsResponse>(
                &query(deps.as_ref(), env.clone(), QueryMsg::RanddropResults {}).unwrap()
            )
            .unwrap(),
            ResultsResponse {
                results: vec![
                    (
                        "nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs".to_string(),
                        Uint128::new(0)
                    ),
                    (
                        "nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve".to_string(),
                        Uint128::new(13500000)
                    )
                ]
            }
        );

        // Check winner data
        assert_eq!(
            from_binary::<ParticipantResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::Participant {
                        address: "nois1tfg9ptr84t9zshxxf5lkvrd6ej7gxjh75lztve".to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            ParticipantResponse {
                participant: Some(ParticipantDataResponse {
                    randomness: Some(
                        HexBinary::from_hex(
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa129",
                        )
                        .unwrap()
                    ),
                    base_randdrop_amount: Uint128::new(4500000),
                    is_winner: Some(true),
                    winning_amount: Some(Uint128::new(13500000)),
                    participate_time: Timestamp::from_nanos(1571797419879305533),
                    claim_time: Some(Timestamp::from_nanos(1571797419879305533)),
                    randdrop_duration: Some(0),
                })
            }
        );
        // Check loser data
        assert_eq!(
            from_binary::<ParticipantResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::Participant {
                        address: "nois1svvyq5hwf6syvn6mklsxsm0ly7jvtla90q7gfs".to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            ParticipantResponse {
                participant: Some(ParticipantDataResponse {
                    randomness: Some(
                        HexBinary::from_hex(
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa129",
                        )
                        .unwrap()
                    ),
                    base_randdrop_amount: Uint128::new(5869),
                    is_winner: Some(false),
                    winning_amount: Some(Uint128::new(0)),
                    participate_time: Timestamp::from_nanos(1571797419879305533),
                    claim_time: Some(Timestamp::from_nanos(1571797464990527866)),
                    randdrop_duration: Some(45),
                })
            }
        );
        // Check not participant data
        assert_eq!(
            from_binary::<ParticipantResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::Participant {
                        address: "miss_did_not_participate".to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            ParticipantResponse { participant: None }
        );
        // Loser tries to play again
        let info = mock_info(test_data_loser.account.as_str(), &[]);
        let msg = ExecuteMsg::Participate {
            amount: test_data_loser.amount,
            proof: test_data_loser.proof,
        };
        let err = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::UserAlreadyParticipated {});
        // Winner tries to play again
        let info = mock_info(test_data_winner.account.as_str(), &[]);
        let msg = ExecuteMsg::Participate {
            amount: test_data_winner.amount,
            proof: test_data_winner.proof,
        };
        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(err, ContractError::UserAlreadyParticipated {});
    }
}
