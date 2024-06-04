use super::identity::SuteraIdentity;
use ring_compat::signature::{ed25519, Verifier};

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
