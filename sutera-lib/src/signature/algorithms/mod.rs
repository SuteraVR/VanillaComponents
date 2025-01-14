pub mod ed25519;
mod macros;

#[cfg(test)]
mod tests;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::macros::algorithm_action;

use super::{Signature, SuteraIdentity};

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Algorithm not supported: {0:?}")]
    AlgorithmNotSupported(SigningAlgorithmKind),
    #[error("Invalid signature: {0}")]
    Signature(Box<dyn std::error::Error>),
    #[error("Invalid public key: {0}")]
    PublicKey(Box<dyn std::error::Error>),
    #[error("Invalid private key: {0}")]
    PrivateKey(Box<dyn std::error::Error>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SigningAlgorithmKind(String);

#[allow(dead_code)]
trait SigningAlgorithm {
    fn is_capable(kind: &SigningAlgorithmKind) -> bool;
    fn sign(data: &[u8], private_key: &str) -> Result<String, SignatureError>;
    fn to_public_key(private_key: &str) -> Result<String, SignatureError>;
    fn verify(data: &[u8], signature: &str, public_key: &str) -> Result<bool, SignatureError>;
    fn generate_private_key<R: CryptoRngCore + ?Sized>(rng: &mut R) -> String;
}

impl SuteraIdentity {
    pub fn verify(&self, data: &[u8], signature: &str) -> Result<bool, SignatureError> {
        algorithm_action!(&self.algorithm => {
            Algorithm::verify(data, signature, &self.public_key)
        })
        .ok_or(SignatureError::AlgorithmNotSupported(
            self.algorithm.clone(),
        ))?
    }
}

impl Signature {
    pub fn verify(&self, data: &[u8]) -> Result<bool, SignatureError> {
        self.identity.verify(data, &self.signature)
    }
}
