use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized,
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
    #[error("Invalid Address")]
    InvalidAddress {},

    #[error("Invalid Amount: {val:?}")]
    InvalidAmount { val: String },

    #[error("Address: {addr:?} not allowlisted")]
    AddressNotAllowListed { addr: String },

    #[error("trying lotto duration of {desired_duration:?} seconds which is hihgher than {max_duration:?} seconds")]
    MaxDurationExceeded {
        max_duration: u64,
        desired_duration: u64,
    },

    #[error("No Funds Provided")]
    NoFundsProvided,

    #[error("Invalid Payment")]
    InvalidPayment,

    #[error("Unauthorized Receive")]
    UnauthorizedReceive,

    #[error("Invalid Randomness")]
    InvalidRandomness,

    #[error("No Depositors")]
    NoDepositors,

    #[error("Lotto Not found")]
    LottoNotFound,

    #[error("Lotto Deposit Stage Ended")]
    LottoDepositStageEnded,

    #[error("The protocol does not own anything in {denom:?} ")]
    ProtocolBalanceDoesNotOwnSuchDenom { denom: String },

    #[error("Contract is paused")]
    ContractIsPaused,

    #[error("Incorrect Rates")]
    IncorrectRates,
}
