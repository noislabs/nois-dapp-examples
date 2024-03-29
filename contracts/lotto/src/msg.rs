use crate::state::Lotto;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Coin, Timestamp, Uint128};
use nois::NoisCallback;

#[cw_serde]
pub struct InstantiateMsg {
    pub manager: String,
    pub nois_proxy: String,
    // commission that will stay in the contract
    pub protocol_commission_percent: u32,
    // commission that will got to the creator of the lotto
    pub creator_commission_percent: u32,
    // list of addresses that lottos can fund from a cut on wins. like addresses for public goods or community pools
    pub recipients_list: Vec<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Anyone can create a new lotto. This will also book a random beacon at the end of the round
    CreateLotto {
        ticket_price: Coin,
        duration_seconds: u64,
        number_of_winners: u32,
        // list of allowlisted addresses that can receive a share of the total prize
        recipients_list: Vec<(String, u32)>,
    },
    // TODO Kais, Update Config
    SetConfig {
        nois_proxy: Option<String>,
        manager: Option<String>,
        lotto_nonce: Option<u64>,
        recipients_list: Option<Vec<String>>,
        protocol_commission_percent: Option<u32>,
        creator_commission_percent: Option<u32>,
        is_paused: Option<bool>,
    },
    UpdateAllowlistedRecipients {
        add: Vec<String>,
        remove: Vec<String>,
    },
    BuyTicket {
        lotto_id: u64,
    },
    //callback contains the randomness from drand (HexBinary) and job_id
    //callback should only be allowed to be called by the proxy contract
    NoisReceive {
        callback: NoisCallback,
    },
    // Withdraw all available balance to the withdrawal address for a specific denom
    WithdrawAll {
        address: String,
        denom: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Get the config state
    #[returns(ConfigResponse)]
    Config {},
    #[returns(LottoResponse)]
    Lotto { lotto_nonce: u64 },
    /// Gets protocol balances in all denoms
    #[returns(ProtocolBalancesResponse)]
    ProtocolBalances {},
    /// Gets lottos in descending order (new to old)
    #[returns(LottosResponse)]
    LottosDesc {
        // If set filters on the creator
        creator: Option<String>,
        // If set filters on active or non active
        is_active: Option<bool>,
        // If set only nonces smaller than this value are returned
        start_after: Option<u64>,
        /// The max number of entries returned. If you set this too high, your query runs out of gas.
        /// When unset, an implementation defined default will be used.
        limit: Option<u64>,
    },
    #[returns(LottosResponse)]
    LottosAsc {
        // If set filters on the creator
        creator: Option<String>,
        // If set filters on active or non active
        is_active: Option<bool>,
        // If set only nonces greater than this value are returned
        start_after: Option<u64>,
        /// The max number of entries returned. If you set this too high, your query runs out of gas.
        /// When unset, an implementation defined default will be used.
        limit: Option<u64>,
    },
}

// GetLotto response, can be null or Lotto
#[cw_serde]
pub struct GetLottoResponse {
    pub lotto: Option<Lotto>,
}

#[cw_serde]
pub struct LottoResponse {
    /// True if expired, False if not expired
    pub is_expired: bool,
    pub nonce: u64,
    pub ticket_price: Coin,
    pub balance: Uint128,
    pub participants: Vec<String>,
    pub expiration: Timestamp, // how to set expiration
    pub winners: Option<Vec<String>>,
    pub creator: String,
    pub number_of_winners: u32,
    pub recipients_list: Vec<(String, u32)>,
}
#[cw_serde]
pub struct LottosResponse {
    /// True if expired, False if not expired
    pub lottos: Vec<LottoResponse>,
}

#[cw_serde]
pub struct ConfigResponse {
    /// manager if none set to info.sender.
    pub manager: String,
    /// Address of the Nois proxy contract
    pub nois_proxy: String,
    /// If set to true the contract is paused
    /// When a contract is paused the creation of lottos is not possible
    pub is_paused: bool,
}

#[cw_serde]
pub struct ProtocolBalancesResponse {
    /// list of all balances in different denoms
    pub balances: Vec<Coin>,
}
