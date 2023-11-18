use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    /// the denom for the bounty to pay the hacker
    pub bounty_denom: String,
}

pub const CONFIG_KEY: &str = "config";
pub const CONFIG: Item<Config> = Item::new(CONFIG_KEY);
pub const NOIS_PROXY: Item<Addr> = Item::new("nois_proxy");

#[cw_serde]
pub struct RandomnessData {
    // The randomness guessed by the hacker
    pub guessed_randomness: HexBinary,
    // The randomness beacon received from the proxy
    pub actual_randomness: Option<HexBinary>,
    // drand round
    pub randomness_round: Option<u64>,
}

pub const GUESSES_HISTORY: Map<(u64, Addr), RandomnessData> = Map::new("hist");
