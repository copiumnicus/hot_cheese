//! QR framing, and nothing else: the payloads are the serde types that already exist.
//!
//! One frame is `<header-json>` `\n` `<raw body bytes>`. serde_json's compact writer emits no
//! newline, so the first one in a frame is unambiguously the end of the header. The header's
//! `sha256` covers the FULL reassembled body, so a multi-part set is verified as one payload
//! and a single-part one gets the same integrity check for free; `part`/`of` are in the schema
//! from day one, so animated QRs are not a version bump.
//!
//! A [`QrKind::SafeTxRequest`] frame carries NO digest, deliberately: a claimed `safeTxHash`
//! would ask a human to compare 64 hex characters, which humans do not do. The signature frame
//! carries the `safe_tx_hash` a [`crate::SignResponse`] already holds, for the MACHINE that
//! collects it to check against the digest it rebuilt itself.
use alloy_primitives::B256;
use err_mac::create_err_with_impls;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Protocol tag: these bytes are a hot_cheese frame of this shape, and no other.
pub const HC: u32 = 1;

/// Body bytes one frame carries. A version-40 byte-mode QR holds 2953, and the header plus its
/// separator is under 160 of them.
pub const BODY_BYTES_PER_FRAME: usize = 2048;

/// Largest body that will be framed or reassembled: what the daemon accepts as a request body,
/// since a QR-delivered intent has to fit through the same door.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

create_err_with_impls!(
    #[derive(Debug)]
    pub QrErr,
    NoFrames,
    NoHeaderSeparator,
    EmptyBody,
    Serde(serde_json::Error)
    ;
    UnknownProtocol { hc: u32 },
    KindMismatch { expected: QrKind, found: QrKind },
    CountMismatch { expected: u16, found: u16 },
    PartOutOfRange { part: u16, of: u16 },
    DuplicatePart { part: u16 },
    MissingPart { part: u16 },
    DigestMismatch { expected: B256, found: B256 },
    PayloadTooLarge { bytes: usize, max: usize }
);

/// What the body of a frame set is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QrKind {
    /// JSON [`crate::intent::Intent`]: the fields to sign, carrying no digest.
    SafeTxRequest,
    /// JSON [`crate::SignResponse`]: one signature and the hash it is over.
    SafeTxSignature,
    /// Raw `policy.toml` bytes.
    Policy,
}

/// The line before the body. An unrecognised term is a refusal, not a silent drop: a frame this
/// build does not fully understand is one it must not reassemble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Reassemble a complete frame set. Every frame must agree on the protocol, the kind, the count
/// and the digest; the parts must be exactly `1..=of`, each once; and the bytes that come out
/// must hash to the digest the frames claim, which is what makes a scan verified rather than
/// merely concatenated.
pub fn reassemble(frames: &[Vec<u8>]) -> Result<(QrKind, Vec<u8>), QrErr> {
    let mut head: Option<QrHeader> = None;
    let mut parts: Vec<Option<&[u8]>> = Vec::new();
    for frame in frames {
        let cut = frame
            .iter()
            .position(|b| *b == b'\n')
            .ok_or(QrErr::NoHeaderSeparator)?;
        let header: QrHeader = serde_json::from_slice(&frame[..cut])?;
        if header.hc != HC {
            return Err(QrErr::UnknownProtocol { hc: header.hc });
        }
        match head {
            None => {
                parts = vec![None; header.of as usize];
                head = Some(header);
            }
            Some(first) => {
                if header.t != first.t {
                    return Err(QrErr::KindMismatch {
                        expected: first.t,
                        found: header.t,
                    });
                }
                if header.of != first.of {
                    return Err(QrErr::CountMismatch {
                        expected: first.of,
                        found: header.of,
                    });
                }
                if header.sha256 != first.sha256 {
                    return Err(QrErr::DigestMismatch {
                        expected: first.sha256,
                        found: header.sha256,
                    });
                }
            }
        }
        let slot = header
            .part
            .checked_sub(1)
            .and_then(|i| parts.get_mut(i as usize))
            .ok_or(QrErr::PartOutOfRange {
                part: header.part,
                of: header.of,
            })?;
        if slot.is_some() {
            return Err(QrErr::DuplicatePart { part: header.part });
        }
        *slot = Some(&frame[cut + 1..]);
    }
    let Some(head) = head else {
        return Err(QrErr::NoFrames);
    };
    let mut body: Vec<u8> = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let Some(part) = part else {
            return Err(QrErr::MissingPart { part: i as u16 + 1 });
        };
        if body.len() + part.len() > MAX_BODY_BYTES {
            return Err(QrErr::PayloadTooLarge {
                bytes: body.len() + part.len(),
                max: MAX_BODY_BYTES,
            });
        }
        body.extend_from_slice(part);
    }
    let found = B256::from_slice(&Sha256::digest(&body));
    if found != head.sha256 {
        return Err(QrErr::DigestMismatch {
            expected: head.sha256,
            found,
        });
    }
    Ok((head.t, body))
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

    /// A body larger than one frame is split, and comes back only when the whole set is there
    /// and hashes to what the headers claim: a flipped byte, a missing part and a repeated part
    /// are each refused rather than silently reassembled into something else.
    #[test]
    fn a_split_body_reassembles_only_intact() {
        let payload = body(BODY_BYTES_PER_FRAME * 2 + 7);
        let set = frames(QrKind::SafeTxRequest, &payload).expect("frame the body");
        assert_eq!(set.len(), 3);
        assert_eq!(
            reassemble(&set).expect("reassemble the set"),
            (QrKind::SafeTxRequest, payload.clone())
        );

        let mut tampered = set.clone();
        let last = tampered[1].len() - 1;
        tampered[1][last] ^= 0xff;
        assert!(matches!(
            reassemble(&tampered),
            Err(QrErr::DigestMismatch { .. })
        ));

        assert!(matches!(
            reassemble(&set[..2]),
            Err(QrErr::MissingPart { part: 3 })
        ));
        let repeated = vec![set[0].clone(), set[0].clone(), set[2].clone()];
        assert!(matches!(
            reassemble(&repeated),
            Err(QrErr::DuplicatePart { part: 1 })
        ));
        assert!(matches!(reassemble(&[]), Err(QrErr::NoFrames)));

        assert!(matches!(
            frames(QrKind::Policy, &body(MAX_BODY_BYTES + 1)),
            Err(QrErr::PayloadTooLarge {
                bytes: _,
                max: MAX_BODY_BYTES
            })
        ));
    }

    /// THE cross-device invariant: an intent that goes out as a QR and comes back parsed must
    /// still be the same transaction. Every field the digest covers rides the U256 codec, the
    /// hex bytes codec or the operation enum, so a lossy one anywhere would move `safe_tx_hash`
    /// — and the far device would sign a transaction nobody read.
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
        let (kind, scanned) = reassemble(&set).expect("scan the frames back");
        assert_eq!(kind, QrKind::SafeTxRequest);
        let Intent::SafeTx(parsed) =
            serde_json::from_slice(&scanned).expect("the scanned bytes are an intent")
        else {
            panic!("a framed SafeTx must scan back as a SafeTx");
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
