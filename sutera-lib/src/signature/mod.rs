pub mod algorithms;
pub mod private_key_masked;
use self::algorithms::SigningAlgorithmKind;
use self::private_key_masked::PrivateKeyMasked;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Signed<T: Clone + DeserializeOwned + Serialize> {
    #[serde(bound(deserialize = "T: DeserializeOwned", serialize = "T: Serialize"))]
    payload: T,
    signature: Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    identity: SuteraIdentity,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SuteraIdentity {
    display_name: String,
    algorithm: SigningAlgorithmKind,
    public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuteraPrivateKey {
    algorithm: SigningAlgorithmKind,
    key: PrivateKeyMasked<String>,
}
