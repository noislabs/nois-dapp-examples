use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Coin, HexBinary, Timestamp, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    /// manager that can change the manager , register merkle or withdraw funds
    pub manager: Addr,
    // The nois-proxy from which to request the randomness
    pub nois_proxy: NoisProxy,
    // denom of the token to randdrop
    pub randdrop_denom: String,
    /// MerkleRoot is hex-encoded merkle root.
    pub merkle_root: HexBinary,
    /// If test_mode is set the state of participant_data can be reset
    pub test_mode: Option<bool>,
}

#[cw_serde]
pub struct NoisProxy {
    // The price to pay the proxy for randomness
    pub price: Coin,
    // The address of the nois-proxy contract deployed onthe same chain as this contract
    pub address: Addr,
}

#[cw_serde]
pub struct ParticipantData {
    // The randomness beacon received from the proxy
    pub randomness: Option<HexBinary>,
    // amount provided during proof
    pub base_randdrop_amount: Uint128,
    // Amount that the paricipate won. This is None until the ranomness arrives. After
    // that it is always set to a value > 0 for winners of 0 for non-winners.
    pub winning_amount: Option<Uint128>,
    // The begin participation time
    pub participate_time: Timestamp,
    // The randdrop claiming time
    pub claim_time: Option<Timestamp>,
}

pub const CONFIG_KEY: &str = "config";
pub const CONFIG: Item<Config> = Item::new(CONFIG_KEY);

/// A map that stores participant addresses and their randdrop state.
pub const PARTICIPANTS: Map<&Addr, ParticipantData> = Map::new("p");
