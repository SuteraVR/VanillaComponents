use std::cell::LazyCell;

use super::{SigningAlgorithm, SigningAlgorithmKind};
use tracing::instrument;
use tracing_error::TracedError;

pub struct Ed25519 {}

impl SigningAlgorithm for Ed25519 {
    fn is_capable(kind: &SigningAlgorithmKind) -> bool {
        kind.0 == "ed25519"
    }

    #[instrument("Ed25519/sign", skip(data, private_key))]
    fn sign(data: &str, private_key: &str) -> Result<String, TracedError<super::SignatureError>> {
        todo!()
    }

    #[instrument("Ed25519/verify", skip(data, signature, public_key))]
    fn verify(
        data: &str,
        signature: &str,
        public_key: &str,
    ) -> Result<String, TracedError<super::SignatureError>> {
        todo!()
    }
}
