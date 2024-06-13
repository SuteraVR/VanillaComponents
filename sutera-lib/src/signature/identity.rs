use std::str::FromStr;

use ring_compat::signature::ed25519;
use thiserror::Error;

/// An error that occurs when parsing a Sutera identity string.
/// Sutera-identity-stringをパースする際に起きるエラー。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SuteraIdentityStringParseError {
    #[error("invalid identity string")]
    InvalidFormat,
    #[error("invalid identity string, version {0} is not supported")]
    VersionMismatch(String),
    #[error("invalid identity string, kind {0} is not supported")]
    UnsupportedKind(String),
}

#[derive(Debug, PartialEq, Eq, Clone, strum::EnumString, strum::AsRefStr)]
pub enum SuteraIdentityKind {
    #[strum(serialize = "user")]
    User,
}

/// A struct representing an identity in the Sutera network.
/// Suteraネットワークにおけるidentityを表す構造体。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuteraIdentity {
    /// The kind of object treated in the Sutera network (e.g., user, server, world etc.)
    /// Suteraネットワークで扱うオブジェクトの種類 (例: ユーザー、サーバー、ワールドなど)
    pub kind: SuteraIdentityKind,

    /// The display name of the identity.  
    /// This is only designated for human-readable purposes and plays no role in authentication.  
    /// display_name can only contain alphanumeric characters (0-9, a-z)
    /// identityの表示名。
    /// これは人間の理解を促進するためだけに定義されており、認証プロセスにおいて何の役目も果たしません。
    /// 表示名には英数字(0-9, a-z)のみを利用することができます。
    pub display_name: Option<String>,

    /// The ed25519 public key of the identity.  
    /// This is used to verify the signature of the identity.
    /// identityのed25519公開鍵です。
    /// identityの署名を検証されるために使用されます。
    pub pub_signature: ed25519::VerifyingKey,
}

/// Convert SuteraIdentity to String.  
/// The format is `{type}@{display_name}.sutera-identity-v1.{pub_signature}`.  
/// Because pub_signature is 32byte, so the part `{pub_signature}` is 64 letters hexadecimal string.  
/// SuteraIdentityを文字列に変換します。
/// 形式は `{type}@{display_name}.sutera-identity-v1.{pub_signature}` です。
/// TODO: ここよく分からない！
///
/// ## Example
/// ```no_test
/// user.sutera-identity-v1.fffffff.....
/// user@alice.sutera-identity-v1.fffffff.....
/// ```
impl From<SuteraIdentity> for String {
    fn from(identity: SuteraIdentity) -> String {
        format!(
            "{}.sutera-identity-v1.{}",
            match identity.display_name {
                Some(display_name) => format!("{}@{}", identity.kind.as_ref(), display_name),
                None => identity.kind.as_ref().to_string(),
            },
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

        let (kind, version, pub_key) = (parts[0].to_string(), parts[1].to_string(), parts[2]);

        if kind.is_empty() {
            return Err(SuteraIdentityStringParseError::InvalidFormat);
        }

        if version != "sutera-identity-v1" {
            return Err(SuteraIdentityStringParseError::VersionMismatch(version));
        }

        if pub_key.len() != 64 {
            return Err(SuteraIdentityStringParseError::InvalidFormat);
        }

        let (kind, display_name) = match kind.find('@') {
            Some(index) => (
                SuteraIdentityKind::from_str(&kind[..index]).map_err(|_| {
                    SuteraIdentityStringParseError::UnsupportedKind(kind[..index].to_string())
                })?,
                Some(kind[index + 1..].to_string()),
            ),
            None => (
                SuteraIdentityKind::from_str(&kind).map_err(|_| {
                    SuteraIdentityStringParseError::UnsupportedKind(kind.to_string())
                })?,
                None,
            ),
        };

        let pub_key_bytes = parts[2]
            .as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16))
            .collect::<Result<Vec<u8>, std::num::ParseIntError>>()
            .or(Err(SuteraIdentityStringParseError::InvalidFormat))?;

        Ok(SuteraIdentity {
            kind,
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
    fn sutera_identity_string() {
        // ダミーの公開鍵(全てのビットが0)のSuteraIdentityを作成, 文字列に変換
        let identity = SuteraIdentity {
            kind: SuteraIdentityKind::User,
            display_name: Some("see2et".to_string()),
            pub_signature: ed25519::VerifyingKey([0; 32]),
        };

        let identity_str: String = identity.clone().into();
        assert_eq!(
            identity_str,
            "user@see2et.sutera-identity-v1.0000000000000000000000000000000000000000000000000000000000000000"
        );

        // 変換した文字列をSuteraIdentityに戻し, オリジナルのSuteraIdentityと一致するか検証
        let parsed_identity: SuteraIdentity = identity_str.try_into().unwrap();
        assert_eq!(identity, parsed_identity);
    }

    #[test]
    fn sutera_identity_string_without_name() {
        // ダミーの公開鍵(全てのビットが0)のSuteraIdentityを作成, 文字列に変換
        let identity = SuteraIdentity {
            kind: SuteraIdentityKind::User,
            display_name: None,
            pub_signature: ed25519::VerifyingKey([0; 32]),
        };

        let identity_str: String = identity.clone().into();
        assert_eq!(
            identity_str,
            "user.sutera-identity-v1.0000000000000000000000000000000000000000000000000000000000000000"
        );

        // 変換した文字列をSuteraIdentityに戻し, オリジナルのSuteraIdentityと一致するか検証
        let parsed_identity: SuteraIdentity = identity_str.try_into().unwrap();
        assert_eq!(identity, parsed_identity);
    }

    #[test]
    fn sutera_identity_string_version_mismatch() {
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
    fn sutera_identity_string_invalid() {
        // 不正な文字列をSuteraIdentityに変換しようとした場合にエラーにちゃんとなるか検証

        let invalid_identity_str = "user.sutera-identity-v1";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str = "user.sutera-identity-v1.abc";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str = "user.sutera-identity-v1.x000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::InvalidFormat)
        );
        let invalid_identity_str = "unknown.sutera-identity-v1.x000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::UnsupportedKind(
                "unknown".to_string()
            ))
        );
        let invalid_identity_str = "unknown@hello.sutera-identity-v1.x000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            SuteraIdentity::try_from(invalid_identity_str.to_string()),
            Err(SuteraIdentityStringParseError::UnsupportedKind(
                "unknown".to_string()
            ))
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
