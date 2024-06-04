use ring_compat::signature::ed25519;
use thiserror::Error;

/// An error that occurs when parsing a Sutera identity string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SuteraIdentityStringParseError {
    #[error("invalid identity string")]
    InvalidFormat,
    #[error("invalid identity string, {0} is not supported")]
    VersionMismatch(String),
}

/// A struct representing an identity in the Sutera network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuteraIdentity {
    /// The display name of the identity.  
    /// This is only designated for human-readable purposes and plays no role in authentication.  
    /// display_name can only contain alphanumeric characters (0-9, a-z)
    pub display_name: String,

    /// The ed25519 public key of the identity.  
    /// This is used to verify the signature of the identity.
    pub pub_signature: ed25519::VerifyingKey,
}

/// Convert SuteraIdentity to String.  
/// The format is `{display_name}.sutera-identity-v1.{pub_signature}`.  
/// Because pub_signature is 32byte, so the part `{pub_signature}` is 64 letters hexadecimal string.  
impl From<SuteraIdentity> for String {
    fn from(identity: SuteraIdentity) -> String {
        format!(
            "{}.sutera-identity-v1.{}",
            identity.display_name,
            identity
                .pub_signature
                .0
                .iter()
                .fold(String::with_capacity(64), |acc, byte| acc
                    + &format!("{:02x}", byte))
        )
    }
}

impl TryFrom<String> for SuteraIdentity {
    type Error = SuteraIdentityStringParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 3 {
            return Err(SuteraIdentityStringParseError::InvalidFormat);
        }

        let (display_name, version, pub_key) =
            (parts[0].to_string(), parts[1].to_string(), parts[2]);

        if display_name.is_empty() {
            return Err(SuteraIdentityStringParseError::InvalidFormat);
        }

        if version != "sutera-identity-v1" {
            return Err(SuteraIdentityStringParseError::VersionMismatch(version));
        }

        if pub_key.len() != 64 {
            return Err(SuteraIdentityStringParseError::InvalidFormat);
        }

        let pub_key_bytes = parts[2]
            .as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16))
            .collect::<Result<Vec<u8>, std::num::ParseIntError>>()
            .or(Err(SuteraIdentityStringParseError::InvalidFormat))?;

        Ok(SuteraIdentity {
            display_name,
            pub_signature: ed25519::VerifyingKey(pub_key_bytes.try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use ring_compat::signature::ed25519;

    #[test]
    fn test_sutera_identity_string() {
        // ダミーの公開鍵(全てのビットが0)のSuteraIdentityを作成, 文字列に変換
        let identity = SuteraIdentity {
            display_name: "see2et".to_string(),
            pub_signature: ed25519::VerifyingKey([0; 32]),
        };

        let identity_str: String = identity.clone().into();
        assert_eq!(
            identity_str,
            "see2et.sutera-identity-v1.0000000000000000000000000000000000000000000000000000000000000000"
        );

        // 変換した文字列をSuteraIdentityに戻し, オリジナルのSuteraIdentityと一致するか検証
        let parsed_identity: SuteraIdentity = identity_str.try_into().unwrap();
        assert_eq!(identity, parsed_identity);
    }

    #[test]
    fn test_sutera_identity_string_version_mismatch() {
        // バージョンが異なる文字列をSuteraIdentityに変換しようとした場合のエラーを検証
        let invalid_identity_str = "see2et.sutera-identity-v2.xxx";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::VersionMismatch(
                "sutera-identity-v2".to_string()
            ))
        );
    }

    #[test]
    fn test_sutera_identity_string_invalid() {
        // 不正な文字列をSuteraIdentityに変換しようとした場合にエラーにちゃんとなるか検証

        let invalid_identity_str = "see2et.sutera-identity-v1";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str = "see2et.sutera-identity-v1.abc";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str = "see2et.sutera-identity-v1.x000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str =
            "sutera-identity-v1.0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str =
            ".sutera-identity-v1.0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
    }
}
