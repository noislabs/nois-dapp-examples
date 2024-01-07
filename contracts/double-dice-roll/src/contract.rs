#[cfg(not(feature = "library"))]
use cosmwasm_std::{ensure_eq, entry_point, Order};
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, StdResult, WasmMsg,
};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{DOUBLE_DICE_OUTCOME, NOIS_PROXY};
use nois::{ints_in_range, NoisCallback, ProxyExecuteMsg, MAX_JOB_ID_LEN};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // The nois-proxy abstracts the IBC and nois chain away from this application
    let nois_proxy_addr = deps
        .api
        .addr_validate(&msg.nois_proxy)
        .map_err(|_| ContractError::InvalidProxyAddress)?;
    NOIS_PROXY.save(deps.storage, &nois_proxy_addr)?;

    set_contract_version(
        deps.storage,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    )?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
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
        //RollDice should be called by a player who wants to roll the dice
        ExecuteMsg::RollDice { job_id } => execute_roll_dice(deps, env, info, job_id),
        //NoisReceive should be called by the proxy contract. The proxy is forwarding the randomness from the nois chain to this contract.
        ExecuteMsg::NoisReceive { callback } => execute_receive(deps, env, info, callback),
    }
}

//execute_roll_dice is the function that will trigger the process of requesting randomness.
//The request from randomness happens by calling the nois-proxy contract
pub fn execute_roll_dice(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    job_id: String,
) -> Result<Response, ContractError> {
    let nois_proxy = NOIS_PROXY.load(deps.storage)?;
    //Prevent a player from paying for an already existing randomness.
    //The actual immutability of the history comes in the execute_receive function
    if DOUBLE_DICE_OUTCOME
        .may_load(deps.storage, &job_id)?
        .is_some()
    {
        return Err(ContractError::JobIdAlreadyPresent);
    }
    validate_job_id(&job_id)?;

    let response = Response::new().add_message(WasmMsg::Execute {
        contract_addr: nois_proxy.into(),
        //GetNextRandomness requests the randomness from the proxy
        //The job id is needed to know what randomness we are referring to upon reception in the callback
        //In this example, the job_id represents one round of dice rolling.
        msg: to_json_binary(&ProxyExecuteMsg::GetNextRandomness { job_id })?,
        // We pay here the contract with the native chain coin.
        // We need to check first with the nois proxy the denoms and amounts that are required
        funds: info.funds, // Just pass on all funds we got
    });
    Ok(response)
}

pub fn validate_job_id(job_id: &str) -> Result<(), ContractError> {
    if job_id.len() > MAX_JOB_ID_LEN {
        Err(ContractError::JobIdTooLong)
    } else {
        Ok(())
    }
}

//The execute_receive function is triggered upon reception of the randomness from the proxy contract
//The callback contains the randomness from drand (HexBinary) and the job_id
pub fn execute_receive(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    callback: NoisCallback,
) -> Result<Response, ContractError> {
    //load proxy address from store
    let proxy = NOIS_PROXY.load(deps.storage)?;
    //callback should only be allowed to be called by the proxy contract
    //otherwise anyone can cut the randomness workflow and cheat the randomness by sending the randomness directly to this contract
    ensure_eq!(info.sender, proxy, ContractError::UnauthorizedReceive);

    // In this Dapp we don't need the drand publish time. so we skip it with ..
    let NoisCallback {
        job_id, randomness, ..
    } = callback;

    let randomness: [u8; 32] = randomness
        .to_array()
        .map_err(|_| ContractError::InvalidRandomness)?;
    //ints_in_range provides a list of random numbers following a uniform distribution within a range.
    //in this case it will provide uniformly randomized numbers between 1 and 6
    let double_dice_outcome = ints_in_range(randomness, 2, 1, 6);
    //summing the dice to fit the real double dice probability distribution from 2 to 12
    let double_dice_outcome = double_dice_outcome.iter().sum();

    //Preserve the immutability of the previous rounds.
    //So that the player cannot retry and change history.
    let response = match DOUBLE_DICE_OUTCOME.may_load(deps.storage, &job_id)? {
        None => Response::default(),
        Some(_randomness) => return Err(ContractError::JobIdAlreadyPresent),
    };
    DOUBLE_DICE_OUTCOME.save(deps.storage, &job_id, &double_dice_outcome)?;

    Ok(response)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetHistoryOfRounds {} => to_json_binary(&query_history(deps)?),
        QueryMsg::QueryOutcome { job_id } => to_json_binary(&query_outcome(deps, job_id)?),
    }
}

//Query the outcome for a sepcific dice roll round/job_id
fn query_outcome(deps: Deps, job_id: String) -> StdResult<Option<u8>> {
    let outcome = DOUBLE_DICE_OUTCOME.may_load(deps.storage, &job_id)?;
    Ok(outcome)
}

//This function shows all the history of the dice outcomes from all rounds/job_ids
fn query_history(deps: Deps) -> StdResult<Vec<String>> {
    let out: Vec<String> = DOUBLE_DICE_OUTCOME
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| item.map(|(id, value)| format!("{id}:{value}")))
        .collect::<StdResult<_>>()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{coins, Timestamp};
    use cosmwasm_std::{Empty, HexBinary, OwnedDeps};

    const CREATOR: &str = "creator";
    const PROXY_ADDRESS: &str = "the proxy of choice";

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            nois_proxy: "address123".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    fn instantiate_proxy() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            nois_proxy: PROXY_ADDRESS.to_string(),
        };
        let info = mock_info(CREATOR, &[]);
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        deps
    }

    #[test]
    fn execute_roll_dice_works() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::RollDice {
            job_id: "1".to_owned(),
        };
        let info = mock_info("guest", &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    }

    #[test]
    fn job_id_too_long() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::RollDice {
            job_id: "abcabcabcabcabca_asfsdfsdgsdgbcbcabcabcabc234t34t3t34gabcabcabc49".to_owned(),
        };
        let info = mock_info("guest", &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::JobIdTooLong));
    }

    #[test]
    fn proxy_cannot_bring_an_existing_job_id() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "round_1".to_string(),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                published: Timestamp::from_seconds(1111111111),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "round_1".to_string(),
                randomness: HexBinary::from_hex(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                )
                .unwrap(),
                published: Timestamp::from_seconds(1111111111),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();

        assert!(matches!(err, ContractError::JobIdAlreadyPresent));

        // we can just call .unwrap() to assert this was a success
    }

    #[test]
    fn execute_receive_fails_for_invalid_randomness() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "round_1".to_string(),
                randomness: HexBinary::from_hex("ffffffff").unwrap(),
                published: Timestamp::from_seconds(1111111111),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();

        assert!(matches!(err, ContractError::InvalidRandomness));
        // we can just call .unwrap() to assert this was a success
    }
    #[test]
    fn players_cannot_request_an_existing_job_id() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "111".to_string(),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                published: Timestamp::from_seconds(1111111111),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let msg = ExecuteMsg::RollDice {
            job_id: "111".to_owned(),
        };
        let info = mock_info("guest", &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::JobIdAlreadyPresent));

        // we can just call .unwrap() to assert this was a success
    }

    #[test]
    fn execute_receive_fails_for_wrong_sender() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "123".to_string(),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                published: Timestamp::from_seconds(1111111111),
            },
        };
        let info = mock_info("guest", &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert!(matches!(err, ContractError::UnauthorizedReceive));
    }
    #[test]
    fn execute_receive_works() {
        let mut deps = instantiate_proxy();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "123".to_string(),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                published: Timestamp::from_seconds(1111111111),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    }
}
