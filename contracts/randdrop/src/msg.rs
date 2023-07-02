use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint128};
use nois::NoisCallback;

#[cw_serde]
pub struct InstantiateMsg {
    /// manager if none set to info.sender.
    pub manager: String,
    /// Address of the Nois proxy contract
    pub nois_proxy_address: String,
    /// Nois proxy prices denom
    pub nois_proxy_denom: String,
    /// Nois proxy prices amount
    pub nois_proxy_amount: Uint128,
    /// Randdrop denom
    pub randdrop_denom: String,
    /// MerkleRoot is hex-encoded merkle root.
    pub merkle_root: HexBinary,
}

#[cw_serde]
pub enum ExecuteMsg {
    UpdateConfig {
        manager: Option<String>,
        nois_proxy_denom: Option<String>,
        nois_proxy_amount: Option<Uint128>,
        nois_proxy_address: Option<String>,
        randdrop_denom: Option<String>,
        merkle_root: Option<HexBinary>,
    },
    // This will trigger fetching the unpredictable random beacon
    Participate {
        /// The amount which is stored in the merkle tree. If a wrong amount is used here,
        /// no entry will be found.
        amount: Uint128,
        /// Proof is hex-encoded merkle proof.
        proof: Vec<HexBinary>,
    },
    // callback contains the randomness from drand (HexBinary) and job_id
    // callback should only be allowed to be called by the proxy contract
    // This entrypoint also claims the randdrop
    // The claim does not check if contract has enough funds, manager must ensure it.
    NoisReceive {
        callback: NoisCallback,
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
    #[returns(HasClaimedResponse)]
    HasClaimed { address: String },
    // An address that is lucky only means that the Nois randomness hashed with the address gives a good match
    // It does not mean that the address was eligible at the first place for the randdrop as there is no way for the contract to check eligibility just by looking at the address.
    #[returns(IsWinnerResponse)]
    IsWinner { address: String },
    /// Query randdrop results
    #[returns(ResultsResponse)]
    RanddropResults {},
}

#[cw_serde]
pub struct ConfigResponse {
    /// manager if none set to info.sender.
    pub manager: String,
    /// Address of the Nois proxy contract
    pub nois_proxy_address: String,
    /// Nois proxy prices denom
    pub nois_proxy_denom: String,
    /// Nois proxy prices amount
    pub nois_proxy_amount: Uint128,
    /// Randdrop denom
    pub randdrop_denom: String,
    /// MerkleRoot is hex-encoded merkle root.
    pub merkle_root: HexBinary,
}

#[cw_serde]
pub struct ResultsResponse {
    pub results: Vec<(String, Uint128)>,
}

#[cw_serde]
pub struct IsWinnerResponse {
    pub is_winner: Option<bool>,
}

#[cw_serde]
pub struct HasClaimedResponse {
    // None means not a participant
    pub has_claimed: Option<bool>,
}

#[cw_serde]
pub struct QueriedRanddropResult {
    pub participant: String,
    pub amount: Uint128,
}
