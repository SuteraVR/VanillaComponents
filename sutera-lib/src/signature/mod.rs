pub mod algorithms;
use self::algorithms::SigningAlgorithm;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct Signed<T: Clone + DeserializeOwned + Serialize> {
    #[serde(bound(deserialize = "T: DeserializeOwned", serialize = "T: Serialize"))]
    payload: T,
    signature: Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Signature {
    identity: SuteraIdentity,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct SuteraIdentity {
    display_name: String,
    algorithm: SigningAlgorithm,
    public_key: String,
}
