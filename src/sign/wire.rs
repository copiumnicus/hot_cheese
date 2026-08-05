//! Wire codec for `U256` fields: serialize as decimal; accept a native integer OR a
//! decimal/0x-hex string (the latter so JSON can carry values above `u64`).
pub mod u256 {
    use alloy_primitives::U256;
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    struct U256Visitor;
    impl Visitor<'_> for U256Visitor {
        type Value = U256;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a u256 as a native integer or a decimal/0x-hex string")
        }
        fn visit_u64<E: Error>(self, v: u64) -> Result<U256, E> {
            Ok(U256::from(v))
        }
        fn visit_i64<E: Error>(self, v: i64) -> Result<U256, E> {
            u64::try_from(v).map(U256::from).map_err(E::custom)
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<U256, E> {
            let t = v.trim();
            if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                U256::from_str_radix(h, 16).map_err(E::custom)
            } else {
                t.parse().map_err(E::custom)
            }
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        d.deserialize_any(U256Visitor)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct W(#[serde(with = "super::u256")] U256);

    /// The hand-written U256 codec: a native integer, a decimal string, and a 0x-hex string
    /// all parse to the same value, and it re-serializes as decimal (not ruint's default hex).
    #[test]
    fn int_dec_and_hex_parse_equal_and_serialize_decimal() {
        let int: W = serde_json::from_str("255").unwrap();
        let dec: W = serde_json::from_str("\"255\"").unwrap();
        let hex: W = serde_json::from_str("\"0xff\"").unwrap();
        assert_eq!(int, dec);
        assert_eq!(dec, hex);
        assert_eq!(dec.0, U256::from(255u64));
        assert_eq!(serde_json::to_string(&dec).unwrap(), "\"255\"");
    }
}
