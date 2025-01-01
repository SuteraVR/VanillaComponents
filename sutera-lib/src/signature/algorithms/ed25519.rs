use std::str::FromStr;

use crate::error::ResultCaptureErrExt;
use crate::util::hex::{from_hex, FromHexError};

use super::{SigningAlgorithm, SigningAlgorithmKind};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use thiserror::Error;
use tracing::instrument;

pub struct Ed25519 {}

#[derive(Debug, Error)]
enum DecodeKeyError {
    #[error("unable to decode hex: {0}")]
    UnableToDecodeHex(#[from] FromHexError),
    #[error("invalid key length: {actual} bytes, expected {expected}")]
    KeyLengthMismatch { actual: usize, expected: usize },
    #[error(transparent)]
    SignatureError(#[from] ed25519_dalek::SignatureError),
}

#[instrument("parse_verifying_key")]
fn parse_verifying_key(value: &str) -> Result<VerifyingKey, DecodeKeyError> {
    let bytes = from_hex(value)?;
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(DecodeKeyError::KeyLengthMismatch {
            actual: bytes.len(),
            expected: PUBLIC_KEY_LENGTH,
        });
    }
    Ok(VerifyingKey::from_bytes(
        &<[u8; PUBLIC_KEY_LENGTH]>::try_from(bytes).unwrap(),
    )?)
}

#[instrument("parse_signing_key")]
fn parse_signing_key(value: &str) -> Result<SigningKey, DecodeKeyError> {
    let bytes = from_hex(value)?;
    if bytes.len() != SECRET_KEY_LENGTH {
        return Err(DecodeKeyError::KeyLengthMismatch {
            actual: bytes.len(),
            expected: SECRET_KEY_LENGTH,
        });
    }
    Ok(SigningKey::from_bytes(
        &<[u8; SECRET_KEY_LENGTH]>::try_from(bytes).unwrap(),
    ))
}

impl SigningAlgorithm for Ed25519 {
    fn is_capable(kind: &SigningAlgorithmKind) -> bool {
        kind.0 == "ed25519"
    }

    #[instrument("sign", skip(data, private_key))]
    fn sign(data: &[u8], private_key: &str) -> Result<String, super::SignatureError> {
        let mut private_key = parse_signing_key(private_key)
            .map_err(|e| super::SignatureError::PrivateKey(Box::new(e)))?;
        Ok(private_key.try_sign(data).capture_and_unwrap().to_string())
    }

    #[instrument("verify", skip(data, signature, public_key))]
    fn verify(
        data: &[u8],
        signature: &str,
        public_key: &str,
    ) -> Result<bool, super::SignatureError> {
        let public_key = parse_verifying_key(public_key)
            .map_err(|e| super::SignatureError::PublicKey(Box::new(e)))?;
        let signature = Signature::from_str(signature)
            .map_err(|e| super::SignatureError::Signature(Box::new(e)))?;
        Ok(public_key.verify_strict(data, &signature).is_ok())
    }
}

// TODO: テストを書く
// TODO: `generate_private`, `to_public` を実装する
