//! Minimal Solana keypair handling without pulling in the transaction SDK.
//!
//! Solana's exported keypair form is the Ed25519 seed followed by its public key. The daemon
//! only generates that 64-byte value and derives its base58 public address; transaction types
//! and signing traits are deliberately outside this crate's boundary.
use err_mac::create_err_with_impls;
use rand::{CryptoRng, RngCore};
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const KEYPAIR_LEN: usize = SECRET_KEY_LEN + PUBLIC_KEY_LEN;

create_err_with_impls!(
    #[derive(Debug)]
    pub SolanaKeyErr,
    InvalidKeypair
    ;
    InvalidLength { found: usize }
);

fn parse(keypair: &[u8]) -> Result<Ed25519KeyPair, SolanaKeyErr> {
    if keypair.len() != KEYPAIR_LEN {
        return Err(SolanaKeyErr::InvalidLength {
            found: keypair.len(),
        });
    }
    Ed25519KeyPair::from_seed_and_public_key(&keypair[..SECRET_KEY_LEN], &keypair[SECRET_KEY_LEN..])
        .map_err(|_| SolanaKeyErr::InvalidKeypair)
}

/// Generate the same 64-byte `seed || public-key` representation Solana CLI keypair files use.
pub fn generate_keypair<R>(rng: &mut R) -> Result<Zeroizing<[u8; KEYPAIR_LEN]>, SolanaKeyErr>
where
    R: CryptoRng + RngCore,
{
    let mut out = Zeroizing::new([0u8; KEYPAIR_LEN]);
    rng.fill_bytes(&mut out[..SECRET_KEY_LEN]);
    let pair = Ed25519KeyPair::from_seed_unchecked(&out[..SECRET_KEY_LEN])
        .map_err(|_| SolanaKeyErr::InvalidKeypair)?;
    out[SECRET_KEY_LEN..].copy_from_slice(pair.public_key().as_ref());
    Ok(out)
}

/// Validate a serialized keypair and return its base58 public address.
pub fn solana_address(keypair: &[u8]) -> Result<String, SolanaKeyErr> {
    let pair = parse(keypair)?;
    Ok(bs58::encode(pair.public_key().as_ref()).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn generated_keypairs_round_trip_to_their_public_address() {
        let keypair = generate_keypair(&mut OsRng).unwrap();
        assert_eq!(
            solana_address(&keypair[..]).unwrap(),
            bs58::encode(&keypair[SECRET_KEY_LEN..]).into_string()
        );
    }

    #[test]
    fn rejects_wrong_lengths_and_inconsistent_public_keys() {
        assert!(matches!(
            solana_address(&[0u8; KEYPAIR_LEN - 1]),
            Err(SolanaKeyErr::InvalidLength { .. })
        ));

        let mut keypair = generate_keypair(&mut OsRng).unwrap();
        keypair[KEYPAIR_LEN - 1] ^= 1;
        assert!(matches!(
            solana_address(&keypair[..]),
            Err(SolanaKeyErr::InvalidKeypair)
        ));
    }
}
