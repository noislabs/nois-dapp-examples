use cosmwasm_std::{
    ensure, ensure_eq, entry_point, to_json_binary, Addr, Attribute, BankMsg, Coin, Deps, DepsMut,
    Empty, Env, HexBinary, MessageInfo, QueryResponse, Response, StdResult, Timestamp, Uint128,
    WasmMsg,
};
use nois::{NoisCallback, ProxyExecuteMsg};
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, IsClaimedResponse, IsLuckyResponse,
    MerkleRootResponse, QueryMsg,
};
use crate::state::{
    Config, RandomnessParams, CLAIMED, CLAIMED_VALUE, CONFIG, MERKLE_ROOT, NOIS_RANDOMNESS,
};
use cw2::set_contract_version;

/// The winning chance is 1/AIRDROP_ODDS
const AIRDROP_ODDS: u64 = 3;

/// This allows the manager to request the beacon up to 3 months in the future
const RANDOM_BEACON_MAX_REQUEST_TIME_IN_THE_FUTURE: u64 = 7890000;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let manager = deps.api.addr_validate(&msg.manager)?;
    let denom = msg.denom;
    let nois_proxy = deps
        .api
        .addr_validate(&msg.nois_proxy)
        .map_err(|_| ContractError::InvalidProxyAddress)?;

    NOIS_RANDOMNESS.save(
        deps.storage,
        &RandomnessParams {
            nois_randomness: None,
            requested: false,
        },
    )?;

    let config = Config {
        manager,
        denom,
        nois_proxy,
    };
    CONFIG.save(deps.storage, &config)?;
    set_contract_version(
        deps.storage,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    )?;
    Ok(Response::default())
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
            nois_proxy,
            denom,
        } => execute_update_config(deps, env, info, manager, denom, nois_proxy),
        ExecuteMsg::RegisterMerkleRoot { merkle_root } => {
            execute_register_merkle_root(deps, env, info, merkle_root)
        }
        //RandDrop should be called by the manager with a future timestamp
        ExecuteMsg::Randdrop {
            random_beacon_after,
        } => execute_randdrop(deps, env, info, random_beacon_after),
        //NoisReceive should be called by the proxy contract. The proxy is forwarding the randomness from the nois chain to this contract.
        ExecuteMsg::NoisReceive { callback } => execute_receive(deps, env, info, callback),
        ExecuteMsg::Claim { amount, proof } => execute_claim(deps, env, info, amount, proof),
        ExecuteMsg::WithdrawAll { address } => execute_withdraw_all(deps, env, info, address),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    let response = match msg {
        QueryMsg::IsLucky { address } => to_json_binary(&query_is_lucky(deps, address)?)?,
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?)?,
        QueryMsg::MerkleRoot {} => to_json_binary(&query_merkle_root(deps)?)?,
        QueryMsg::IsClaimed { address } => to_json_binary(&query_is_claimed(deps, address)?)?,
    };
    Ok(response)
}

fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    manager: Option<String>,
    denom: Option<String>,
    nois_proxy: Option<String>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    // check the calling address is the authorised multisig
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    let manager = match manager {
        Some(ma) => deps.api.addr_validate(&ma)?,
        None => config.manager,
    };
    let nois_proxy = match nois_proxy {
        Some(prx) => deps.api.addr_validate(&prx)?,
        None => config.nois_proxy,
    };
    let denom = denom.unwrap_or(config.denom);

    CONFIG.save(
        deps.storage,
        &Config {
            manager,
            denom,
            nois_proxy,
        },
    )?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

// This function will call the proxy and ask for the randomness round
pub fn execute_randdrop(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    random_beacon_after: Timestamp,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    // check the calling address is the authorised multisig
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    // For full transparency make sure the merkle root has been registered before beacon request
    if MERKLE_ROOT.may_load(deps.storage)?.is_none() {
        return Err(ContractError::MerkleRootAbsent);
    }

    // check that the timestamp is between now and the safety time
    // to make sure the operator did not make a typo
    let block_time = env.block.time;
    ensure!(
        block_time < random_beacon_after,
        ContractError::RandomAfterIsInThePast {
            block_time,
            random_beacon_after
        }
    );
    let max_allowed_beacon_time =
        block_time.plus_seconds(RANDOM_BEACON_MAX_REQUEST_TIME_IN_THE_FUTURE);
    ensure!(
        max_allowed_beacon_time > random_beacon_after,
        ContractError::RandomAfterIsTooMuchInTheFuture {
            max_allowed_beacon_time
        }
    );

    let RandomnessParams {
        nois_randomness,
        requested,
    } = NOIS_RANDOMNESS.load(deps.storage)?;
    // Prevents requesting randomness twice.
    if requested {
        return Err(ContractError::ImmutableRandomness);
    }
    NOIS_RANDOMNESS.save(
        deps.storage,
        &RandomnessParams {
            nois_randomness,
            requested: true,
        },
    )?;

    let response = Response::new().add_message(WasmMsg::Execute {
        contract_addr: config.nois_proxy.into_string(),
        // GetRandomnessAfter requests the randomness from the proxy after a specific timestamp
        // The job id is needed to know what randomness we are referring to upon reception in the callback.
        // In this example we only need 1 random number so this can be hardcoded to "airdrop"
        msg: to_json_binary(&ProxyExecuteMsg::GetRandomnessAfter {
            after: random_beacon_after,
            job_id: "airdrop".to_string(),
        })?,
        // We pay here the proxy contract with whatever the manager sends. The manager needs to check in advance the proxy prices.
        funds: info.funds, // Just pass on all funds we got
    });
    Ok(response)
}

pub fn execute_receive(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    callback: NoisCallback,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let RandomnessParams {
        nois_randomness,
        requested,
    } = NOIS_RANDOMNESS.load(deps.storage)?;

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
    // Make sure the randomness does not exist yet

    match nois_randomness {
        None => NOIS_RANDOMNESS.save(
            deps.storage,
            &RandomnessParams {
                nois_randomness: Some(randomness),
                requested,
            },
        ),
        Some(_randomness) => return Err(ContractError::ImmutableRandomness),
    }?;

    Ok(Response::default())
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

    let amount = deps
        .querier
        .query_balance(env.contract.address, config.denom)?;
    let msg = BankMsg::Send {
        to_address: address,
        amount: vec![amount],
    };
    let res = Response::new()
        .add_message(msg)
        .add_attribute("action", "withdraw_all");
    Ok(res)
}

fn is_randomly_eligible(sender: &Addr, randomness: [u8; 32]) -> bool {
    let sender_hash: [u8; 32] = Sha256::digest(sender.as_bytes()).into();

    // Hash the combined value using SHA256 to generate a random number between 1 and 3
    let mut hasher = Sha256::new();
    // Concatenate the randomness and sender hash values
    hasher.update(randomness);
    hasher.update(sender_hash);
    let hash = hasher.finalize();

    // The u64 range is large compared to the modulo, so the distribution is expected to be good enough.
    // See https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
    let hash_u64 = u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);
    // returns true iff the address is eligible
    hash_u64 % AIRDROP_ODDS == 0
}

fn execute_register_merkle_root(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    merkle_root: HexBinary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let current_merkle_root = MERKLE_ROOT.may_load(deps.storage)?;

    // check the calling address is the authorised multisig
    ensure_eq!(info.sender, config.manager, ContractError::Unauthorized);

    if current_merkle_root.is_some() {
        return Err(ContractError::MerkleImmutable {});
    }

    if merkle_root.len() != 32 {
        return Err(ContractError::WrongLength {});
    }

    MERKLE_ROOT.save(deps.storage, &merkle_root)?;

    Ok(Response::new().add_attributes(vec![
        Attribute::new("action", "register_merkle_root"),
        Attribute::new("merkle_root", merkle_root.to_string()),
    ]))
}

fn execute_claim(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
    proof: Vec<HexBinary>,
) -> Result<Response, ContractError> {
    // verify not claimed
    let claimed = CLAIMED.has(deps.storage, &info.sender);
    if claimed {
        return Err(ContractError::Claimed {});
    }
    let merkle_root = MERKLE_ROOT.load(deps.storage)?;

    // "nois1blabla...chksum4500000" -> hash
    let user_input = format!("{}{}", info.sender, amount);
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
    if merkle_root != hash {
        return Err(ContractError::VerificationFailed {});
    }

    // Check that the sender is lucky enough to be randomly eligible for the randdrop
    let nois_randomness = NOIS_RANDOMNESS.load(deps.storage)?.nois_randomness;

    match nois_randomness {
        Some(randomness) => match is_randomly_eligible(&info.sender, randomness) {
            true => Ok(()),
            false => Err(ContractError::NotRandomlyEligible {}),
        },
        None => Err(ContractError::RandomnessUnavailable {}),
    }?;

    // Update claim
    CLAIMED.save(deps.storage, &info.sender, &CLAIMED_VALUE)?;
    let config = CONFIG.load(deps.storage)?;

    let send_amount = Coin {
        amount: amount * Uint128::from(AIRDROP_ODDS),
        denom: config.denom,
    };

    let res = Response::new()
        .add_message(BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: vec![send_amount.clone()],
        })
        .add_attributes(vec![
            Attribute::new("action", "claim"),
            Attribute::new("address", info.sender),
            Attribute::new("merkle_amount", amount), // value from the merkle tree
            Attribute::new("send_amount", send_amount.to_string()), // actual send amount
        ]);
    Ok(res)
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        manager: config.manager.to_string(),
    })
}

fn query_is_lucky(deps: Deps, address: String) -> StdResult<IsLuckyResponse> {
    let address = deps.api.addr_validate(address.as_str())?;
    // Check if the address is lucky to be randomly selected for the randdrop
    let nois_randomness = NOIS_RANDOMNESS.load(deps.storage)?.nois_randomness;

    let is_lucky = nois_randomness.map(|randomness| is_randomly_eligible(&address, randomness));
    Ok(IsLuckyResponse { is_lucky })
}

fn query_merkle_root(deps: Deps) -> StdResult<MerkleRootResponse> {
    let merkle_root = MERKLE_ROOT.load(deps.storage)?;
    let resp = MerkleRootResponse { merkle_root };

    Ok(resp)
}

fn query_is_claimed(deps: Deps, address: String) -> StdResult<IsClaimedResponse> {
    let address = deps.api.addr_validate(&address)?;
    let is_claimed = CLAIMED.has(deps.storage, &address);
    let resp = IsClaimedResponse { is_claimed };

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Empty, HexBinary, OwnedDeps, SubMsg};
    use serde::Deserialize;

    const CREATOR: &str = "creator";
    const PROXY_ADDRESS: &str = "the proxy of choice";
    const MANAGER: &str = "manager1";

    fn instantiate_contract() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            manager: MANAGER.to_string(),
            nois_proxy: PROXY_ADDRESS.to_string(),
            denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                .to_string(),
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
        let config: ConfigResponse = from_json(&res).unwrap();
        assert_eq!(MANAGER, config.manager.as_str());
    }
    #[test]
    fn instantiate_fails_for_invalid_proxy_address() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            manager: MANAGER.to_string(),
            nois_proxy: "".to_string(),
            denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                .to_string(),
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
            nois_proxy: "nois_proxy".to_string(),
            denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                .to_string(),
        };

        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // update manager
        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::UpdateConfig {
            manager: Some("manager2".to_string()),
            nois_proxy: None,
            denom: None,
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(&res).unwrap();
        assert_eq!("manager2", config.manager.as_str());

        // Unauthorized err
        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::UpdateConfig {
            manager: None,
            nois_proxy: None,
            denom: None,
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});
    }

    #[test]
    fn register_merkle_root() {
        let mut deps = instantiate_contract();

        // register new merkle root
        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: HexBinary::from_hex("634de21cde").unwrap(),
        };
        let err = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap_err();
        assert_eq!(err, ContractError::WrongLength {});
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: HexBinary::from_hex(
                "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37",
            )
            .unwrap(),
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                Attribute::new("action", "register_merkle_root"),
                Attribute::new(
                    "merkle_root",
                    "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37"
                )
            ]
        );

        let res = query(deps.as_ref(), env, QueryMsg::MerkleRoot {}).unwrap();
        let merkle_root: MerkleRootResponse = from_json(&res).unwrap();
        assert_eq!(
            HexBinary::from_hex("634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37")
                .unwrap(),
            merkle_root.merkle_root
        );
        // registering a new merkle root should fail
        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: HexBinary::from_hex(
                "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37",
            )
            .unwrap(),
        };
        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(err, ContractError::MerkleImmutable {});
    }

    const TEST_DATA: &[u8] = include_bytes!("../testdata/nois_testnet_005_test_data.json");
    const TEST_DATA_LIST: &[u8] = include_bytes!("../testdata/nois_testnet_005_list.json");

    #[derive(Deserialize, Debug)]
    struct Encoded {
        account: String,
        amount: Uint128,
        root: HexBinary,
        proofs: Vec<HexBinary>,
    }
    #[derive(Deserialize, Debug)]
    struct Account {
        address: Addr,
        //amount: u64,
    }
    #[derive(Deserialize, Debug)]
    struct AirdropList {
        airdrop_list: Vec<Account>,
    }

    #[test]
    fn execute_rand_drop_works() {
        let mut deps = instantiate_contract();

        let msg = ExecuteMsg::Randdrop {
            random_beacon_after: Timestamp::from_seconds(1571797419),
        };
        let info = mock_info("guest", &[]);
        // Only manager should be able to request the randomness
        let err = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let info = mock_info(MANAGER, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap_err();
        assert_eq!(err, ContractError::MerkleRootAbsent {});

        let info = mock_info(MANAGER, &[]);
        let msg_merkle = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: HexBinary::from_hex(
                "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37",
            )
            .unwrap(),
        };
        execute(deps.as_mut(), mock_env(), info, msg_merkle).unwrap();

        let info = mock_info(MANAGER, &[]);
        let err = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::RandomAfterIsInThePast {
                block_time: Timestamp::from_nanos(1571797419879305533),
                random_beacon_after: Timestamp::from_seconds(1571797419)
            }
        );
        let msg = ExecuteMsg::Randdrop {
            random_beacon_after: Timestamp::from_seconds(1579687420),
        };
        let err = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::RandomAfterIsTooMuchInTheFuture {
                max_allowed_beacon_time: Timestamp::from_nanos(1579687419879305533),
            }
        );

        let msg = ExecuteMsg::Randdrop {
            random_beacon_after: Timestamp::from_seconds(1577565357),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg.clone()).unwrap();

        // Cannot request randomness more than once
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::ImmutableRandomness {});
    }

    #[test]
    fn execute_receive_works() {
        let mut deps = instantiate_contract();

        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "123".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            },
        };
        let info = mock_info("some_random_account", &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap_err();
        // Only proxy should call this entrypoint
        assert_eq!(err, ContractError::UnauthorizedReceive {});
        let info = mock_info(PROXY_ADDRESS, &[]);
        execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();
        let info = mock_info(PROXY_ADDRESS, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        // Proxy should cannot call this entrypoint if there's already randomness in state
        assert_eq!(err, ContractError::ImmutableRandomness {});
    }

    #[test]
    fn claim() {
        // Run test 1
        let mut deps = instantiate_contract();
        let test_data: Encoded = from_json(TEST_DATA).unwrap();

        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Receive randomness
        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "123".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa127",
                )
                .unwrap(),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            proof: test_data.proofs,
        };

        let env = mock_env();
        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let expected = SubMsg::new(BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: vec![Coin {
                amount: Uint128::new(13500000), // 4500000*3
                denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                    .to_string(),
            }],
        });
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.attributes,
            vec![
                Attribute::new("action", "claim"),
                Attribute::new("address", test_data.account.clone()),
                Attribute::new("merkle_amount", test_data.amount),
                Attribute::new(
                    "send_amount",
                    Coin {
                        amount: test_data.amount * Uint128::new(AIRDROP_ODDS as u128),
                        denom:
                            "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                                .to_string(),
                    }
                    .to_string()
                ),
            ]
        );

        assert!(
            from_json::<IsClaimedResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::IsClaimed {
                        address: test_data.account
                    }
                )
                .unwrap()
            )
            .unwrap()
            .is_claimed
        );
        // Try and claim again
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Claimed {});

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
        let res = execute(deps.as_mut(), env, info, msg).unwrap();

        let expected = SubMsg::new(BankMsg::Send {
            to_address: "withdraw_address".to_string(),
            amount: vec![Coin {
                amount: Uint128::new(0),
                denom: "ibc/717352A5277F3DE916E8FD6B87F4CA6A51F2FBA9CF04ABCFF2DF7202F8A8BC50"
                    .to_string(),
            }],
        });
        assert_eq!(res.messages, vec![expected]);
    }

    #[test]
    fn randomness_elgibility_distribution_is_correct() {
        let mut deps = instantiate_contract();
        let test_data_json: Encoded = from_json(TEST_DATA).unwrap();
        let merkle_root = test_data_json.root;

        let test_data: AirdropList = from_json(TEST_DATA_LIST).unwrap();

        let env = mock_env();
        let info = mock_info(MANAGER, &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot { merkle_root };
        execute(deps.as_mut(), env, info, msg).unwrap();

        // Receive randomness
        let msg = ExecuteMsg::NoisReceive {
            callback: NoisCallback {
                job_id: "123".to_string(),
                published: Timestamp::from_seconds(1682086395),
                randomness: HexBinary::from_hex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa124",
                )
                .unwrap(),
            },
        };
        let info = mock_info(PROXY_ADDRESS, &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let mut num_lucky = 0;
        for addr in &test_data.airdrop_list {
            let response: IsLuckyResponse = from_json(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsLucky {
                        address: addr.address.to_string(),
                    },
                )
                .unwrap(),
            )
            .unwrap();

            if response.is_lucky.unwrap_or_default() {
                num_lucky += 1;
            }
        }
        // We have 51 participants. We accept +/- 20%.
        let expected = test_data.airdrop_list.len() / AIRDROP_ODDS as usize;
        assert!(num_lucky >= expected * 80 / 100, "{num_lucky} winners");
        assert!(num_lucky <= expected * 120 / 100, "{num_lucky} winners");
    }
}
