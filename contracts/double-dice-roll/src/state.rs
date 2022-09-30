use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub const NOIS_PROXY: Item<Addr> = Item::new("nois_proxy");
pub const DOUBLE_DICE_OUTCOME: Map<&str, u8> = Map::new("double_dice_outcome");
