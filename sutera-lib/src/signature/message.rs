use std::str::FromStr;

use super::identity::SuteraIdentity;
use ring_compat::signature::{ed25519, Signer, Verifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A common structure of message exchanged within the Sutera network.
/// Suteraネットワークにおけるメッセージの送受信に使用される構造体です。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuteraSignedMessage {
    pub author: SuteraIdentity,
    pub message: String,
    pub signature: ed25519::Signature,
}

/// An error that occurs when signing a message.
/// メッセージの署名時に起きるエラー。
#[derive(Debug, Error)]
pub enum SuteraMessageSigningError {
    #[error("the signing key does not match the author's verifying key")]
    SigningKeyMismatch,
}

impl SuteraSignedMessage {
    /// Sign a message with the author's signing key.
    /// 署名者の署名鍵でメッセージを署名する。
    ///
    /// ## Parameters / パラメーター
    /// - `author`: The author of the message. / メッセージの署名者。
    /// - `message`: The content of the message. / メッセージの内容。
    /// - `signer`: The signing key of the author. / 署名者の署名鍵。
    ///
    /// ## Returns / 戻り値
    /// A new signed message.
    /// if the signing key does not match the author's verifying key, return `Err`.
    /// 新たに署名されたメッセージが返却されます。
    /// 署名鍵が署名者の認証鍵と合致しない場合、`Err`が返却されます。
    pub fn new(
        author: SuteraIdentity,
        message: String,
        signer: ed25519::SigningKey,
    ) -> Result<Self, SuteraMessageSigningError> {
        let verifying_key = signer.verifying_key();
        if verifying_key != author.pub_signature {
            return Err(SuteraMessageSigningError::SigningKeyMismatch);
        }

        let signature = signer.sign(message.as_bytes());

        Ok(SuteraSignedMessage {
            author,
            message,
            signature,
        })
    }

    /// Check if the signature is valid.
    /// 署名が有効かどうかを確認します。
    ///
    /// **SuteraSignedMessage should be verified before processing the message.**
    /// **SuteraSignedMessageはメッセージが処理される前に検証されなければいけません。**
    ///
    /// **The signature is once checked at the time of creation in normal scenario,**
    /// **so this method is used as a assertion.**
    /// **署名は通常の場合、作成されたタイミングで一度検証されます。**
    /// **そのため、このメソッドはアサーションとして利用されます。**
    ///
    /// ## Return / 戻り値
    /// `true` if the signature is valid, otherwise `false`.
    /// 署名が有効な場合は`true`、そうでない場合は`false`を返します。
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

#[cfg(test)]
mod tests {
    use crate::signature::identity::SuteraIdentityKind;

    use super::*;
    use pretty_assertions::assert_eq;
    use rand_core::{OsRng, RngCore};

    fn test_signed_message() -> SuteraSignedMessage {
        // ランダムな秘密鍵を生成
        let mut ed25519_seed = [0u8; 32];
        OsRng.fill_bytes(&mut ed25519_seed);
        let secret = ed25519::SigningKey::from_bytes(&ed25519_seed);

        // 秘密鍵からSuteraIdentityを生成
        let identity = SuteraIdentity {
            kind: SuteraIdentityKind::User,
            display_name: Some("see2et".to_string()),
            pub_signature: secret.verifying_key(),
        };

        // 適当なStringをメッセージとして用意し,署名する
        let message = "Hello, Sutera!";
        SuteraSignedMessage::new(identity, message.to_string(), secret).unwrap()
    }

    #[test]
    fn sign_message() {
        // ランダムな秘密鍵で署名されたメッセージを生成
        let mut signed_message = test_signed_message();

        // 署名検証を通過することを確認
        assert!(signed_message.verify());

        // 内容を変更し,改竄されたメッセージとして署名検証に失敗することを確認
        signed_message.message = "Hello, Sutera?".to_string();
        assert!(!signed_message.verify());
    }

    #[test]
    fn signed_message_serializable() {
        // ランダムな秘密鍵で署名されたメッセージを生成
        let signed_message = test_signed_message();

        // シリアライズ -> デシリアライズしても内容が変わらないことを確認
        let serialized = serde_json::to_string(&signed_message).unwrap();
        let deserialized: SuteraSignedMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(signed_message, deserialized);
    }
}
