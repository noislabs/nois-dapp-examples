use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Timestamp, Uint128};
use nois::NoisCallback;

#[cw_serde]
pub struct InstantiateMsg {
    /// manager if none set to info.sender.
    pub manager: String,
    /// Address of the Nois proxy contract
    pub nois_proxy: String,
    /// Randdrop denom
    pub denom: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    UpdateConfig {
        manager: Option<String>,
        nois_proxy: Option<String>,
        denom: Option<String>,
    },
    RegisterMerkleRoot {
        /// MerkleRoot is hex-encoded merkle root.
        merkle_root: HexBinary,
    },
    // This will trigger fetching the unpredictable random beacon that will serve to give the randdrop to only a subset of accounts
    Randdrop {
        random_beacon_after: Timestamp,
    },
    //callback contains the randomness from drand (HexBinary) and job_id
    //callback should only be allowed to be called by the proxy contract
    NoisReceive {
        callback: NoisCallback,
    },
    /// Claim does not check if contract has enough funds, manager must ensure it.
    Claim {
        /// The amount which is stored in the merkle tree. If a wrong amount is used here,
        /// no entry will be found.
        amount: Uint128,
        /// Proof is hex-encoded merkle proof.
        proof: Vec<HexBinary>,
    },
    // Withdraw all available balance of the AIRDROP DENOM to the withdrawal address
    WithdrawAll {
        address: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    Config {},
    #[returns(MerkleRootResponse)]
    MerkleRoot {},
    #[returns(IsClaimedResponse)]
    IsClaimed { address: String },
    // An address that is lucky only means that the Nois randomness hashed with the address gives a good match
    // It does not mean that the address was eligible at the first place for the randdrop as there is no way for the contract to check eligibility just by looking at the address.
    #[returns(IsLuckyResponse)]
    IsLucky { address: String },
}

#[cw_serde]
pub struct ConfigResponse {
    pub manager: String,
}

#[cw_serde]
pub struct IsLuckyResponse {
    pub is_lucky: Option<bool>,
}

#[cw_serde]
pub struct MerkleRootResponse {
    /// MerkleRoot is hex-encoded merkle root.
    pub merkle_root: HexBinary,
}

#[cw_serde]
pub struct IsClaimedResponse {
    pub is_claimed: bool,
}

#[cw_serde]
pub struct MigrateMsg {}
