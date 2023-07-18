use thiserror::Error;

use cosmwasm_std::StdError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized.")]
    Unauthorized,

    #[error("Proxy address is not valid")]
    InvalidProxyAddress,

    #[error("Manager address is not valid")]
    InvalidManagerAddress,

    #[error("Invalid input")]
    InvalidInput {},

    #[error("Wrong Merkle root length")]
    WrongMerkleRootLength {},

    #[error("Verification failed")]
    VerificationFailed {},

    #[error("The sender is not a winner in the randdrop")]
    NotLucky {},

    #[error("The claiming phase did not start. The random beacon is yet to be fetched")]
    RandomnessUnavailable {},

    #[error("Cannot migrate from different contract type: {previous_contract}")]
    CannotMigrate { previous_contract: String },

    // callback should only be allowed to be called by the proxy contract
    // otherwise anyone can cut the randomness workflow and cheat the randomness
    #[error("Unauthorized Receive execution")]
    UnauthorizedReceive,

    #[error("Received invalid randomness")]
    InvalidRandomness,

    #[error("Invalid Proof")]
    InvalidProof,

    #[error("Contract is not in test mode")]
    ContractIsNotInTestMode,

    #[error("The sender address has already requested randomness and maybe received the result")]
    UserAlreadyParticipated,
}
