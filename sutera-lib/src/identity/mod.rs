use ring_compat::signature::ed25519;

/// A struct representing an identity in the Sutera network.
pub struct SuteraIdentity {
    /// The display name of the identity.  
    /// This is only designated for human-readable purposes and plays no role in authentication.
    /// display_name can only contain alphanumeric characters (0-9, A-z)
    pub display_name: String,

    /// The ed25519 public key of the identity.
    /// This is used to verify the signature of the identity.
    pub pub_signature: ed25519::VerifyingKey,
}

impl From<SuteraIdentity> for String {
    fn from(identity: SuteraIdentity) -> String {
        format!(
            "{}.sutera-identity-v1.{}",
            identity.display_name,
            identity
                .pub_signature
                .0
                .iter()
                .fold(String::new(), |acc, byte| acc + &format!("{:02x}", byte))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring_compat::signature::ed25519;

    #[test]
    fn test_sutera_identity() {
        let identity = SuteraIdentity {
            display_name: "Alice".to_string(),
            pub_signature: ed25519::VerifyingKey([0; 32]),
        };

        let identity_str: String = identity.into();
        assert_eq!(identity_str, "Alice.sutera-identity-v1.");
    }
}
