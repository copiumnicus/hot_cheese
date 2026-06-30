//! Non-destructive migration: legacy Web3 keystores (Keychain master) → envelope (DEK).
//!
//! Reads each old key with the legacy `decrypt_key`, re-encrypts it under the new
//! DEK, and verifies both a decrypt round-trip and the re-derived identity before
//! finalizing. The old store is never modified.
//!
//! Flow: stage into `<new_store>.staging` (same filesystem), verify every key, then
//! atomically `rename` each verified file into a freshly-created `new_store`. Any
//! failure tears the staging dir down and leaves `old_store` byte-for-byte intact.
use crate::crypto::envelope::{decrypt_file, encrypt_file, Dek};
use crate::crypto::CryptoErr;
use crate::server::{is_valid_string_name, sk_to_adr, ApiBackendErr};
use err_mac::create_err_with_impls;
use sha2::{Digest, Sha256};
use solana_signer::Signer;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// NOTE: `create_err_with_impls!` matches bare `Variant` / `Variant(Type)` tokens and
// does NOT accept attributes (incl. doc comments) on individual variants — keep them
// undocumented here. Each tuple variant with a type gets a `From` impl for free.
//
//   NewStoreNotEmpty      `new_store` already holds a key file; refuse to clobber it.
//   VerifyMismatch(name)  round-trip or re-derived-identity check failed for `name`.
//   SolanaKeypair         a 64-byte secret did not parse as a Solana keypair.
//   Address(..)           `sk_to_adr` failed to derive an EVM address from 32 bytes.
create_err_with_impls!(
    #[derive(Debug)]
    pub MigrateErr,
    NewStoreNotEmpty,
    VerifyMismatch(String),
    SolanaKeypair,
    StdIo(std::io::Error),
    Crypto(CryptoErr),
    Envelope(crate::crypto::envelope::EnvErr),
    Address(ApiBackendErr)
    ;
);

/// One migrated key: `(name, address-or-hash)` for the operator manifest.
#[derive(Debug)]
pub struct MigratedKey {
    pub name: String,
    pub identity: String,
}

/// Derive the public identity of a decrypted secret purely from its length:
/// 32 → EVM address, 64 → Solana pubkey, otherwise → `sha256:<hex>` of the bytes.
///
/// Because the kind is a function of length alone and the envelope round-trip
/// preserves length, re-running this on the round-tripped bytes and comparing the
/// strings is a sound identity check.
fn derive_identity(plaintext: &[u8]) -> Result<String, MigrateErr> {
    match plaintext.len() {
        32 => Ok(sk_to_adr(plaintext)?),
        64 => {
            let keypair = solana_keypair::Keypair::from_bytes(plaintext)
                .map_err(|_| MigrateErr::SolanaKeypair)?;
            Ok(keypair.pubkey().to_string())
        }
        _ => {
            let digest = Sha256::digest(plaintext);
            Ok(format!("sha256:{}", hex::encode(digest)))
        }
    }
}

/// Sibling staging directory next to `new_store` (e.g. `store` → `store.staging`),
/// guaranteed on the same filesystem so the finalizing `rename` is atomic.
fn staging_dir(new_store: &Path) -> PathBuf {
    let mut name = new_store
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| OsString::from("hot_cheese_store"));
    name.push(".staging");
    match new_store.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

/// True if `dir` exists and contains at least one migratable key file (a regular
/// file whose name passes [`is_valid_string_name`]).
fn has_key_files(dir: &Path) -> Result<bool, MigrateErr> {
    if !dir.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            if is_valid_string_name(name) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Collect the names of migratable key files in `old_store`, sorted for a
/// deterministic manifest. Skips dirs, dotfiles, and `keyring.json` (none of which
/// pass [`is_valid_string_name`], since `.` is rejected).
fn enumerate_keys(old_store: &Path) -> Result<Vec<String>, MigrateErr> {
    let mut names = Vec::new();
    for entry in fs::read_dir(old_store)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue, // non-UTF-8 names can't be valid key names
        };
        if is_valid_string_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Re-encrypt every legacy key in `old_store` under `dek` into `new_store`, verifying
/// each. `old_master` is the legacy Keychain master (fetched by the caller after Touch ID).
///
/// Non-destructive and verify-before-finalize: keys are staged and fully verified
/// before `new_store` is created; on any error the staging dir is removed and
/// `old_store` is left untouched.
pub fn run(
    old_store: &Path,
    old_master: &[u8],
    new_store: &Path,
    dek: &Dek,
) -> Result<Vec<MigratedKey>, MigrateErr> {
    if has_key_files(new_store)? {
        return Err(MigrateErr::NewStoreNotEmpty);
    }

    // Fresh staging dir on the same filesystem as `new_store`. Nuke a stale one first.
    let staging = staging_dir(new_store);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;

    let names = enumerate_keys(old_store)?;

    // Anything that fails inside the loop tears down `staging` and aborts; the `?`
    // operator can't run our cleanup, so we drive the body through a closure and
    // handle the Result explicitly.
    let migrated = match stage_and_verify(old_store, old_master, &staging, dek, &names) {
        Ok(m) => m,
        Err(e) => {
            // Best-effort cleanup; surface the original error regardless.
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    // All verified. Materialize `new_store` and move each staged file in atomically.
    fs::create_dir_all(new_store)?;
    for key in &migrated {
        fs::rename(staging.join(&key.name), new_store.join(&key.name))?;
    }
    fs::remove_dir_all(&staging)?;

    tracing::info!(count = migrated.len(), "migration finalized");
    Ok(migrated)
}

/// Decrypt → record identity → re-encrypt → verify, for every name, into `staging`.
/// Returns the manifest on full success; the caller is responsible for cleaning up
/// `staging` if this returns `Err`.
fn stage_and_verify(
    old_store: &Path,
    old_master: &[u8],
    staging: &Path,
    dek: &Dek,
    names: &[String],
) -> Result<Vec<MigratedKey>, MigrateErr> {
    let mut migrated = Vec::with_capacity(names.len());
    for name in names {
        // a. Decrypt the legacy keystore (MAC-checked inside `decrypt_key`).
        let mut plaintext = crate::crypto::decrypt_key(old_store.join(name), old_master)?;

        // b. Record the public identity from the original bytes.
        let identity = derive_identity(&plaintext)?;

        // c. Re-encrypt under the new DEK into staging (AAD = name).
        encrypt_file(staging, name, dek, &plaintext)?;

        // d. Verify: round-trip the ciphertext AND re-derive the identity from the
        //    decrypted bytes; both must match before we trust this file.
        let mut roundtrip = decrypt_file(&staging.join(name), name, dek)?;
        let ok = roundtrip == plaintext && derive_identity(&roundtrip)? == identity;

        // e. Zeroize both secret buffers regardless of outcome.
        plaintext.zeroize();
        roundtrip.zeroize();

        if !ok {
            return Err(MigrateErr::VerifyMismatch(name.clone()));
        }

        tracing::debug!(name = %name, "key staged and verified");
        migrated.push(MigratedKey {
            name: name.clone(),
            identity,
        });
    }
    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_key, to_vec};

    /// Unique temp dir per test invocation so parallel test runs don't collide.
    fn fresh_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("hot_cheese_migrate_{tag}_{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    const PASSWORD: &str = "migrate-test-password";

    /// Build a legacy `old_store` holding one EVM, one Solana, and one opaque-bytes
    /// key, returning the store path and the three (name, expected-identity) pairs.
    fn make_legacy_store(root: &Path) -> (PathBuf, Vec<(String, String)>) {
        let old_store = root.join("old_store");
        fs::create_dir_all(&old_store).expect("mk old_store");
        let mut rng = rand::thread_rng();

        // EVM: 32-byte secret with a known address (reuse the repo fixture secret).
        let evm_sk =
            to_vec("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829").unwrap();
        let evm_id = sk_to_adr(&evm_sk).expect("evm addr");
        encrypt_key(&old_store, &mut rng, &evm_sk, PASSWORD, "EVM_KEY").expect("enc evm");

        // Solana: a real 64-byte keypair.
        let sol_kp = solana_keypair::Keypair::new();
        let sol_bytes = sol_kp.to_bytes();
        let sol_id = sol_kp.pubkey().to_string();
        encrypt_key(&old_store, &mut rng, sol_bytes, PASSWORD, "SOLANA_KEY").expect("enc sol");

        // Opaque bytes: an off-size secret hashed to sha256.
        let raw = vec![0xABu8; 48];
        let raw_id = format!("sha256:{}", hex::encode(Sha256::digest(&raw)));
        encrypt_key(&old_store, &mut rng, &raw, PASSWORD, "RAW_KEY").expect("enc raw");

        // Decoy non-key file that must be ignored by enumeration.
        fs::write(old_store.join("keyring.json"), b"{}").expect("write decoy");

        (
            old_store,
            vec![
                ("EVM_KEY".to_string(), evm_id),
                ("SOLANA_KEY".to_string(), sol_id),
                ("RAW_KEY".to_string(), raw_id),
            ],
        )
    }

    /// Snapshot every file's bytes in a dir (sorted), to prove non-destructiveness.
    fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for entry in fs::read_dir(dir).expect("read_dir snapshot") {
            let entry = entry.expect("entry");
            if entry.file_type().expect("ft").is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                out.push((name, fs::read(entry.path()).expect("read file")));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    #[test]
    fn migrate_roundtrips_all_kinds_and_preserves_old_store() {
        let root = fresh_dir("happy");
        let (old_store, expected) = make_legacy_store(&root);
        let new_store = root.join("new_store");

        let before = snapshot(&old_store);
        let dek = Dek::random();
        let migrated = run(&old_store, PASSWORD.as_bytes(), &new_store, &dek).expect("run ok");

        // Identities returned must match the directly-derived addresses, by name.
        assert_eq!(migrated.len(), expected.len());
        for (name, ident) in &expected {
            let got = migrated
                .iter()
                .find(|m| &m.name == name)
                .unwrap_or_else(|| panic!("missing migrated key {name}"));
            assert_eq!(&got.identity, ident, "identity mismatch for {name}");
        }

        // Each new file decrypts under the DEK back to the original legacy secret.
        for (name, _) in &expected {
            let migrated_secret =
                decrypt_file(&new_store.join(name), name, &dek).expect("decrypt new");
            let legacy_secret =
                crate::crypto::decrypt_key(old_store.join(name), PASSWORD).expect("decrypt old");
            assert_eq!(migrated_secret, legacy_secret, "secret changed for {name}");
        }

        // The decoy non-key file must NOT have been migrated.
        assert!(!new_store.join("keyring.json").exists());

        // old_store must be byte-identical afterwards.
        assert_eq!(before, snapshot(&old_store), "old_store was modified");

        // Staging dir must be gone.
        assert!(!staging_dir(&new_store).exists(), "staging not cleaned up");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_refuses_when_new_store_already_has_a_key() {
        let root = fresh_dir("nonempty");
        let (old_store, _) = make_legacy_store(&root);
        let new_store = root.join("new_store");
        fs::create_dir_all(&new_store).expect("mk new_store");
        // A pre-existing key file (valid name) must block migration.
        encrypt_file(&new_store, "EXISTING", &Dek::random(), b"squatter").expect("seed new");

        let dek = Dek::random();
        let res = run(&old_store, PASSWORD.as_bytes(), &new_store, &dek);
        assert!(matches!(res, Err(MigrateErr::NewStoreNotEmpty)));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_old_key_aborts_and_leaves_no_staging() {
        let root = fresh_dir("corrupt");
        let (old_store, _) = make_legacy_store(&root);
        let new_store = root.join("new_store");

        // Corrupt one legacy keystore so its MAC/decrypt fails.
        fs::write(old_store.join("EVM_KEY"), b"not a valid keystore").expect("corrupt");

        let before = snapshot(&old_store);
        let dek = Dek::random();
        let res = run(&old_store, PASSWORD.as_bytes(), &new_store, &dek);

        // It must abort (the corrupt file is not a valid keystore JSON / fails MAC).
        assert!(res.is_err(), "expected migration to abort on corrupt key");
        // No staging dir left behind.
        assert!(!staging_dir(&new_store).exists(), "staging dir leaked");
        // new_store must not have been created/populated.
        assert!(!new_store.join("SOLANA_KEY").exists());
        assert!(!new_store.join("RAW_KEY").exists());
        // old_store untouched (besides our own corruption).
        assert_eq!(before, snapshot(&old_store), "old_store was modified");

        let _ = fs::remove_dir_all(&root);
    }
}
