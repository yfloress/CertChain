//! Fixed-size values, serialized as hex in JSON.

use serde::{Deserialize, Serialize};

macro_rules! hex_bytes {
    ($name:ident, $len:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(pub [u8; $len]);

        impl TryFrom<String> for $name {
            type Error = hex::FromHexError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let mut bytes = [0u8; $len];
                hex::decode_to_slice(value, &mut bytes)?;
                Ok(Self(bytes))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                hex::encode(value.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }
    };
}

hex_bytes!(Digest, 32);
hex_bytes!(PublicKey, 32);
hex_bytes!(Signature, 64);
hex_bytes!(Salt, 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_json_round_trip() {
        let digest = Digest([0xab; 32]);
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), digest);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(serde_json::from_str::<Digest>("\"abcd\"").is_err());
    }
}
