use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub const NOIS_PROXY: Item<Addr> = Item::new("nois_proxy");
pub const DOUBLE_DICE_OUTCOME: Map<&str, u8> = Map::new("double_dice_outcome");

pub const RANDOMNESS_LIFECYCLE_BLOCKS: Map<&str, RandomnessLifecycleBlocks> =
    Map::new("randomness_lifecycle_blocks");

/// The blocks when randomness was requested and received. This is used for performance metrics purposes
#[cw_serde]
pub struct RandomnessLifecycleBlocks {
    pub request_block_height: u64,
    pub request_tx_index: u32,
    pub received_block_height: Option<u64>,
    pub received_tx_index: Option<u32>,
}
