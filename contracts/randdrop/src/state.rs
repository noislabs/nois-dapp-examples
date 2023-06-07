use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Coin, HexBinary, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    /// manager that can change the manager , register merkle or withdraw funds
    pub manager: Addr,
    // The nois-proxy from which to request the randomness
    pub nois_proxy: NoisProxy,
    // denom of the token to randdrop
    pub randdrop_denom: String,
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
    pub nois_randomness: Option<[u8; 32]>,
    // amount provided during proof
    pub randdrop_amount: Uint128,
    // true if the participant won
    pub is_winner: Option<bool>,
}

pub const CONFIG_KEY: &str = "config";
pub const CONFIG: Item<Config> = Item::new(CONFIG_KEY);

pub const MERKLE_ROOT_PREFIX: &str = "merkle_root";
pub const MERKLE_ROOT: Item<HexBinary> = Item::new(MERKLE_ROOT_PREFIX);

pub const PARTICIPANTS_PREFIX: &str = "participants";
/// A map that stores participant addresses. Think of this as a set.
pub const PARTICIPANTS: Map<&Addr, ParticipantData> = Map::new(PARTICIPANTS_PREFIX);

pub const CLAIMED_PREFIX: &str = "claimed";
pub const CLAIMED: Map<&Addr, ()> = Map::new(CLAIMED_PREFIX);
