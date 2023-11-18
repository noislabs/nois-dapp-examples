use cosmwasm_std::HexBinary;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use nois::NoisCallback;

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct InstantiateMsg {
    pub nois_proxy: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // guessed randomness
    GuessNextRandomness { randomness: HexBinary },
    //callback contains the randomness from drand (HexBinary) and job_id
    //callback should only be allowed to be called by the proxy contract
    NoisReceive { callback: NoisCallback },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    QueryOutcome { job_id: String },
    GetHistoryOfRounds {},
}
