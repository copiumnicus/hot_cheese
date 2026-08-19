//! QR framing, and nothing else: the payloads are the serde types that already exist.
//!
//! One frame is `<header-json>` `\n` `<raw body bytes>`. serde_json's compact writer emits no
//! newline, so the first one in a frame is unambiguously the end of the header. The header's
//! `sha256` covers the FULL body rather than the frame's slice of it, so whatever collects a set
//! verifies one payload; `part`/`of` are in the schema from day one, so animated QRs are not a
//! version bump.
//!
//! A [`QrKind::SafeTxRequest`] frame carries NO digest of the transaction, deliberately: a
//! claimed `safeTxHash` would ask a human to compare 64 hex characters, which humans do not do.
//!
//! This is the DISPLAY half, and it is the whole module. hot_cheese has no camera and no
//! scanner, so nothing here reads a frame back: an untrusted-input path with no caller is a hole
//! with no user, and it is not kept warm on the chance that someone writes the other half later.
use alloy_primitives::B256;
use err_mac::create_err_with_impls;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Protocol tag: these bytes are a hot_cheese frame of this shape, and no other.
pub const HC: u32 = 1;

/// Body bytes one frame carries. A version-40 byte-mode QR holds 2953, and the header plus its
/// separator is under 160 of them.
pub const BODY_BYTES_PER_FRAME: usize = 2048;

/// Largest body that will be framed: what the daemon accepts as a request body, since a
/// QR-delivered intent has to fit through the same door.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

create_err_with_impls!(
    #[derive(Debug)]
    pub QrErr,
    EmptyBody,
    Serde(serde_json::Error)
    ;
    PayloadTooLarge { bytes: usize, max: usize }
);

/// What the body of a frame set is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QrKind {
    /// JSON [`crate::intent::Intent`]: the fields to sign, carrying no digest.
    SafeTxRequest,
}

/// The line before the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct QrHeader {
    /// Protocol tag; must be [`HC`].
    pub hc: u32,
    /// Which body follows.
    pub t: QrKind,
    /// This frame's 1-based index.
    pub part: u16,
    /// How many frames the whole body takes.
    pub of: u16,
    /// SHA-256 of the full body, identical in every frame of the set.
    pub sha256: B256,
}

/// Frame `body` for display: each frame is its header JSON, a newline, and that frame's slice.
pub fn frames(kind: QrKind, body: &[u8]) -> Result<Vec<Vec<u8>>, QrErr> {
    if body.is_empty() {
        return Err(QrErr::EmptyBody);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(QrErr::PayloadTooLarge {
            bytes: body.len(),
            max: MAX_BODY_BYTES,
        });
    }
    let sha256 = B256::from_slice(&Sha256::digest(body));
    let of = body.chunks(BODY_BYTES_PER_FRAME).count() as u16;
    let mut out = Vec::with_capacity(of as usize);
    for (i, chunk) in body.chunks(BODY_BYTES_PER_FRAME).enumerate() {
        let mut frame = serde_json::to_vec(&QrHeader {
            hc: HC,
            t: kind,
            part: i as u16 + 1,
            of,
            sha256,
        })?;
        frame.push(b'\n');
        frame.extend_from_slice(chunk);
        out.push(frame);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::safe_tx_hash;
    use crate::intent::{Intent, Operation, SafeTxIntent};
    use alloy_primitives::{Address, Bytes, U256};

    fn body(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push((i % 251) as u8);
        }
        out
    }

    fn split(frame: &[u8]) -> (String, &[u8]) {
        let cut = frame
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("a header ends at the first newline");
        (
            String::from_utf8(frame[..cut].to_vec()).expect("the header is JSON text"),
            &frame[cut + 1..],
        )
    }

    /// A body over the frame ceiling is split into consecutive parts whose slices are the body
    /// and nothing else, and every frame states the digest of the WHOLE body rather than of its
    /// own slice — which is what lets a collector verify one payload instead of a concatenation.
    #[test]
    fn a_split_body_frames_under_one_digest_of_the_whole() {
        let payload = body(BODY_BYTES_PER_FRAME * 2 + 7);
        let set = frames(QrKind::SafeTxRequest, &payload).expect("frame the body");
        assert_eq!(set.len(), 3);

        let digest = format!("{}", B256::from_slice(&Sha256::digest(&payload)));
        let mut rejoined = Vec::new();
        for (at, frame) in set.iter().enumerate() {
            let (header, chunk) = split(frame);
            assert!(header.contains(&format!("\"part\":{}", at + 1)), "{header}");
            assert!(header.contains("\"of\":3"), "{header}");
            assert!(header.contains(&digest), "{header}");
            assert!(chunk.len() <= BODY_BYTES_PER_FRAME);
            rejoined.extend_from_slice(chunk);
        }
        assert_eq!(rejoined, payload);

        assert!(matches!(
            frames(QrKind::SafeTxRequest, &body(MAX_BODY_BYTES + 1)),
            Err(QrErr::PayloadTooLarge {
                bytes: _,
                max: MAX_BODY_BYTES
            })
        ));
        assert!(matches!(
            frames(QrKind::SafeTxRequest, &[]),
            Err(QrErr::EmptyBody)
        ));
    }

    /// THE cross-device invariant: an intent that goes out as a QR body and comes back parsed
    /// must still be the same transaction. Every field the digest covers rides the U256 codec,
    /// the hex bytes codec or the operation enum, so a lossy one anywhere would move
    /// `safe_tx_hash` — and the far device would sign a transaction nobody read.
    #[test]
    fn an_intent_keeps_its_digest_across_a_frame() {
        let intent = SafeTxIntent {
            key: "TRADER".into(),
            safe: Address::from([0x11u8; 20]),
            chain_id: U256::from(8453u64),
            to: Address::from([0x22u8; 20]),
            value: U256::MAX,
            data: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb, 0xde, 0xad, 0x00, 0xff]),
            operation: Operation::Delegatecall,
            safe_tx_gas: U256::from(21_000u64),
            base_gas: U256::from(1_000_000_000_000_000_000u64),
            gas_price: U256::from(7u64),
            gas_token: Address::from([0x44u8; 20]),
            refund_receiver: Address::from([0x55u8; 20]),
            nonce: U256::from(u64::MAX),
        };
        let sent = safe_tx_hash(&intent);

        let json = serde_json::to_vec(&Intent::SafeTx(intent)).expect("serialize the intent");
        let set = frames(QrKind::SafeTxRequest, &json).expect("frame the intent");
        assert_eq!(set.len(), 1);
        let (_, framed) = split(&set[0]);
        let Intent::SafeTx(parsed) =
            serde_json::from_slice(framed).expect("the framed bytes are an intent")
        else {
            panic!("a framed SafeTx must read back as a SafeTx");
        };

        assert_eq!(safe_tx_hash(&parsed), sent);
        assert_eq!(
            safe_tx_hash(&SafeTxIntent {
                key: "PHONE".into(),
                ..parsed
            }),
            sent,
            "the keystore name is outside the digest, which is what lets a device rebind it"
        );
    }
}
