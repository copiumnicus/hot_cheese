//! Serialization of Vec<u8> to 0x prefixed hex string
use super::to_vec;
use serde::{de::Error, Deserialize, Deserializer, Serializer};
use std::borrow::Cow;

pub fn serialize<S, T>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    serializer.serialize_str(
        format!(
            "0x{}",
            bytes
                .as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join("")
                .to_string()
        )
        .as_str(),
    )
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let prefixed_hex_str = Cow::<str>::deserialize(deserializer)?;
    to_vec(&prefixed_hex_str).ok_or(D::Error::custom("failtovec"))
}

#[cfg(test)]
mod tests {

    #[derive(Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
    struct S {
        #[serde(with = "super")]
        b: Vec<u8>,
    }

    #[test]
    fn json() {
        let orig = S { b: vec![0, 1] };
        let serialized = serde_json::to_value(&orig).unwrap();
        let expected = serde_json::json!({
            "b": "0x0001"
        });
        assert_eq!(serialized, expected);
        let deserialized: S = serde_json::from_value(expected).unwrap();
        assert_eq!(orig, deserialized);
    }
}
