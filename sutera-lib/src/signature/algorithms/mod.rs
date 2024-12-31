pub mod ed25519;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing_error::TracedError;

#[derive(Error, Debug)]
enum SignatureError {
    #[error("Invalid signature: {0}")]
    Signature(Box<dyn std::error::Error>),
    #[error("Invalid public key: {0}")]
    PublicKey(Box<dyn std::error::Error>),
    #[error("Invalid private key: {0}")]
    PrivateKey(Box<dyn std::error::Error>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SigningAlgorithmKind(String);

pub trait SigningAlgorithm {
    fn is_capable(kind: &SigningAlgorithmKind) -> bool;
    fn sign(data: &str, private_key: &str) -> Result<String, TracedError<SignatureError>>;
    fn verify(
        data: &str,
        signature: &str,
        public_key: &str,
    ) -> Result<String, TracedError<SignatureError>>;
}
