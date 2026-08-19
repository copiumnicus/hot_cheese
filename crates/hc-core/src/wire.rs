//! Wire codec for `U256` fields: serialize as decimal; accept a native integer OR a
//! decimal/0x-hex string (the latter so JSON can carry values above `u64`).
use serde::de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;

/// A JSON value whose object visitor refuses a repeated key at every nesting level. This is
/// deliberately parsed before conversion to the requested Rust type: internally tagged serde
/// enums may otherwise buffer through a representation that keeps only one of two equal keys.
struct NoDuplicates(Value);

impl<'de> Deserialize<'de> for NoDuplicates {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicatesVisitor)
    }
}

struct NoDuplicatesVisitor;

impl<'de> Visitor<'de> for NoDuplicatesVisitor {
    type Value = NoDuplicates;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::Bool(value)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::Number(Number::from(value))))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .map(NoDuplicates)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::String(value.to_string())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::String(value)))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicates(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(NoDuplicates(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(NoDuplicates(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let NoDuplicates(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(NoDuplicates(Value::Object(values)))
    }
}

/// Deserialize JSON while rejecting repeated object keys anywhere in the document. Security
/// boundaries use this instead of serde_json's `Value` path so two consumers cannot disagree
/// about whether the first or last spelling of a privileged field wins.
pub fn strict_json_from_slice<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    let NoDuplicates(value) = serde_json::from_slice(bytes)?;
    serde_json::from_value(value)
}

/// String counterpart to [`strict_json_from_slice`].
pub fn strict_json_from_str<T: DeserializeOwned>(text: &str) -> serde_json::Result<T> {
    strict_json_from_slice(text.as_bytes())
}

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
                if h.is_empty() || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(E::custom("u256 hex is one or more 0-9a-f digits"));
                }
                return U256::from_str_radix(h, 16)
                    .map_err(|_| E::custom("u256 hex exceeds 256 bits"));
            }
            if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(E::custom("u256 decimal is one or more 0-9 digits"));
            }
            U256::from_str_radix(t, 10).map_err(|_| E::custom("u256 decimal exceeds 256 bits"))
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        d.deserialize_any(U256Visitor)
    }
}

/// The same codec element-wise, for a list of `U256` (an adapter manifest's `chain_ids`).
pub mod u256_list {
    use alloy_primitives::U256;
    use serde::{Deserialize, Deserializer};

    #[derive(Deserialize)]
    struct Element(#[serde(with = "super::u256")] U256);

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<U256>, D::Error> {
        let elements = Vec::<Element>::deserialize(d)?;
        let mut out = Vec::with_capacity(elements.len());
        for element in elements {
            out.push(element.0);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::strict_json_from_str;
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

    /// ruint reads `0b1010` as 10 and an empty or prefix-only string as 0, so this codec takes
    /// strict decimal or strict `0x` hex only and never echoes an input byte into the error.
    #[test]
    fn u256_strings_are_strictly_decimal_or_0x_hex() {
        for rejected in [
            "", " ", "_", "0x", "0X", "0x_", "0b1010", "0o17", "1_000", "+1", "-1", "0x0x1", "12a",
            "0xg", "1 0",
        ] {
            let quoted = serde_json::to_string(rejected).unwrap();
            assert!(
                serde_json::from_str::<W>(&quoted).is_err(),
                "{rejected:?} is not a u256"
            );
        }
        for (text, value) in [
            ("0", 0u64),
            ("255", 255),
            ("0xff", 255),
            ("0XFF", 255),
            (" 42 ", 42),
        ] {
            let quoted = serde_json::to_string(text).unwrap();
            let parsed: W = serde_json::from_str(&quoted).expect(text);
            assert_eq!(parsed.0, U256::from(value), "{text}");
        }
        let hostile = serde_json::from_str::<W>("\"1\\u001b[31m\"")
            .expect_err("an escape sequence is not a digit");
        assert!(!hostile.to_string().contains('\u{1b}'), "{hostile}");
    }

    #[test]
    fn strict_json_refuses_duplicate_keys_at_every_depth() {
        for duplicate in [
            r#"{"kind":"one","kind":"two"}"#,
            r#"{"outer":{"amount":"1","amount":"2"}}"#,
            r#"[{"safe":1,"safe":2}]"#,
        ] {
            let error = strict_json_from_str::<serde_json::Value>(duplicate)
                .expect_err("a repeated key must be ambiguous");
            assert!(error.to_string().contains("duplicate JSON object key"));
        }
        let clean: serde_json::Value = strict_json_from_str(r#"{"outer":{"amount":"1"}}"#).unwrap();
        assert_eq!(clean["outer"]["amount"], "1");
    }
}
