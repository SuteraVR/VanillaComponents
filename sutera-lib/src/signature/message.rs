use std::str::FromStr;

use super::identity::SuteraIdentity;
use ring_compat::signature::{ed25519, Verifier};
use serde::{Deserialize, Serialize};

/// A common structure of message exchanged within the Sutera network.
pub struct SuteraSignedMessage {
    pub author: SuteraIdentity,
    pub message: String,
    pub signature: ed25519::Signature,
}

impl SuteraSignedMessage {
    /// Check if the signature is valid.
    ///
    /// **SuteraSignedMessage should be verified before processing the message.**
    ///
    /// **The signature is once checked at the time of creation in normal scenario,**
    /// **so this method is used as a assertion.**
    ///
    /// ## Return
    /// `true` if the signature is valid, otherwise `false`.
    pub fn verify(&self) -> bool {
        self.author
            .pub_signature
            .verify(self.message.as_bytes(), &self.signature)
            .is_ok()
    }
}

impl Serialize for SuteraSignedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let payload = SuteraSignedMessagePayload {
            author: self.author.clone().into(),
            message: self.message.clone(),
            signature: self.signature.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SuteraSignedMessage {
    fn deserialize<D>(deserializer: D) -> Result<SuteraSignedMessage, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = SuteraSignedMessagePayload::deserialize(deserializer)?;
        let author = SuteraIdentity::try_from(payload.author).map_err(serde::de::Error::custom)?;
        let signature =
            ed25519::Signature::from_str(&payload.signature).map_err(serde::de::Error::custom)?;

        Ok(SuteraSignedMessage {
            author,
            message: payload.message,
            signature,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SuteraSignedMessagePayload {
    pub author: String,
    pub message: String,
    pub signature: String,
}
