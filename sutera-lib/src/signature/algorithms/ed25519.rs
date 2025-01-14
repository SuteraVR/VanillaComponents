use std::str::FromStr;

use crate::error::ResultCaptureErrExt;
use crate::signature::SuteraPrivateKey;
use crate::util::hex::{from_hex, to_hex, FromHexError, HexString};

use super::{SigningAlgorithm, SigningAlgorithmKind};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand_core::CryptoRngCore;
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
fn parse_signing_key<T: HexString + ?Sized>(value: &T) -> Result<SigningKey, DecodeKeyError> {
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

    #[instrument("sign", skip_all)]
    fn sign(data: &[u8], private_key: &SuteraPrivateKey) -> Result<String, super::SignatureError> {
        let mut private_key = parse_signing_key(&private_key.key)
            .map_err(|e| super::SignatureError::PrivateKey(Box::new(e)))?;
        Ok(private_key.try_sign(data).capture_and_unwrap().to_string())
    }

    #[instrument("to_public_key", skip_all)]
    fn to_public_key(private_key: &SuteraPrivateKey) -> Result<String, super::SignatureError> {
        let private_key = parse_signing_key(&private_key.key)
            .map_err(|e| super::SignatureError::PrivateKey(Box::new(e)))?;
        Ok(to_hex(&private_key.verifying_key().to_bytes()))
    }

    #[instrument("generate_private_key", skip_all)]
    fn generate_private_key<R: CryptoRngCore + ?Sized>(rng: &mut R) -> SuteraPrivateKey {
        let private_key = SigningKey::generate(rng);
        SuteraPrivateKey {
            key: to_hex(&private_key.to_bytes()).into(),
            algorithm: SigningAlgorithmKind("ed25519".into()),
        }
    }

    #[instrument("verify", skip_all)]
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
