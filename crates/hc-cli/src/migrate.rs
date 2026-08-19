//! Non-destructive migration: legacy Web3 keystores (Keychain master) → envelope (DEK).
//!
//! Reads each old key with the legacy `decrypt_key`, re-encrypts it under the new
//! DEK as a sealed v2 keystore, and verifies both a decrypt round-trip and the
//! re-derived identity before finalizing. The old store is never modified.
//!
//! Every key lands [`KeyUse::SignOnly`] unless the operator named it `shareable`:
//! a key their services fetch over `/read` must be named, or those reads break.
//!
//! Flow: stage into a random, exclusively-created sibling directory, verify every key, then
//! create-only hard-link each verified inode into `new_store`. A normal publication failure
//! rolls back only links made by this invocation; no existing path is ever replaced. Any
//! failure tears our staging dir down and leaves `old_store` byte-for-byte intact.
use err_mac::create_err_with_impls;
use hashbrown::HashSet;
use hc_core::crypto::envelope::{decrypt_file, encrypt_file, Dek, KeyUse};
use hc_core::crypto::CryptoErr;
use hc_core::is_valid_key_name;
use hc_core::solana::solana_address;
use hc_daemon::{sk_to_adr, ApiBackendErr};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

// NOTE: `create_err_with_impls!` matches bare `Variant` / `Variant(Type)` tokens and
// does NOT accept attributes (incl. doc comments) on individual variants — keep them
// undocumented here. Each tuple variant with a type gets a `From` impl for free.
//
//   NewStoreNotEmpty       `new_store` holds a key or unrecognised entry; refuse to clobber it.
//   VerifyMismatch(name)   round-trip or re-derived-identity check failed for `name`.
//   SolanaKeypair          a 64-byte secret did not parse as a Solana keypair.
//   Address(..)            `sk_to_adr` failed to derive an EVM address from 32 bytes.
//   UnknownShareable{name} `--shareable <name>` named a key `old_store` does not hold.
//   WrongNewStore{..}      the CLI destination is not this initialized installation's store.
create_err_with_impls!(
    #[derive(Debug)]
    pub MigrateErr,
    NewStoreNotEmpty,
    VerifyMismatch(String),
    SolanaKeypair,
    StdIo(std::io::Error),
    Crypto(CryptoErr),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Address(ApiBackendErr)
    ;
    UnknownShareable { name: String },
    WrongNewStore { expected: PathBuf, found: PathBuf }
);

/// One migrated key, for the operator manifest.
#[derive(Debug)]
pub struct MigratedKey {
    /// Keystore name, identical in the old and new store.
    pub name: String,
    /// EVM address, Solana pubkey, or `sha256:<hex>` of the secret.
    pub identity: String,
    /// The use it was sealed under.
    pub key_use: KeyUse,
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
        64 => solana_address(plaintext).map_err(|_| MigrateErr::SolanaKeypair),
        _ => {
            let digest = Sha256::digest(plaintext);
            Ok(format!("sha256:{}", hex::encode(digest)))
        }
    }
}

const STAGING_PREFIX: &str = ".hot_cheese_migrate_";
const STAGING_SUFFIX: &str = ".staging";

fn store_parent(new_store: &Path) -> Result<&Path, MigrateErr> {
    if new_store.file_name().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "new store must name a directory",
        )
        .into());
    }
    Ok(new_store
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".")))
}

/// Return whether the initialized destination already exists. Only its own keyring and Git
/// metadata may predate migration. A valid key name blocks regardless of file type, so a
/// symlink or directory cannot survive preflight and be replaced during publication.
fn destination_is_clear(dir: &Path) -> Result<bool, MigrateErr> {
    let metadata = match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_dir() => metadata,
        Ok(_) => return Err(MigrateErr::NewStoreNotEmpty),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_dir() {
        return Err(MigrateErr::NewStoreNotEmpty);
    }

    for (at, entry) in fs::read_dir(dir)?.enumerate() {
        if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "store has too many entries",
            )
            .into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(MigrateErr::NewStoreNotEmpty);
        };
        let file_type = entry.file_type()?;
        let expected_metadata = (name == hc_core::keyring::KEYRING_FILE && file_type.is_file())
            || (name == ".git" && file_type.is_dir());
        if is_valid_key_name(name) || !expected_metadata {
            return Err(MigrateErr::NewStoreNotEmpty);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_dir() && metadata.dev() == self.dev && metadata.ino() == self.ino
    }
}

/// A random directory this invocation created exclusively. Drop only removes the pathname if
/// it still names that same inode, so even a hostile replacement cannot make cleanup recursive
/// over somebody else's directory.
struct StagingDir {
    path: PathBuf,
    identity: FileIdentity,
    directory: OpenDir,
    names: Vec<String>,
}

impl StagingDir {
    fn create(new_store: &Path) -> Result<Self, MigrateErr> {
        let parent = store_parent(new_store)?;
        fs::create_dir_all(parent)?;
        for _ in 0..8 {
            let mut random = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let path = parent.join(format!(
                "{STAGING_PREFIX}{}{STAGING_SUFFIX}",
                hex::encode(random)
            ));
            let result = fs::DirBuilder::new().mode(0o700).create(&path);
            match result {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&path)?;
                    let identity = FileIdentity::of(&metadata);
                    let directory = match OpenDir::open(&path) {
                        Ok(directory) if identity.matches(&directory.0.metadata()?) => directory,
                        Ok(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "migration staging directory changed during creation",
                            )
                            .into())
                        }
                        Err(error) => {
                            if fs::symlink_metadata(&path)
                                .is_ok_and(|current| identity.matches(&current))
                            {
                                let _ = fs::remove_dir(&path);
                            }
                            return Err(error.into());
                        }
                    };
                    return Ok(Self {
                        path,
                        identity,
                        directory,
                        names: Vec::new(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a migration staging directory",
        )
        .into())
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn record(&mut self, name: &str) {
        self.names.push(name.to_string());
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        // Staging is flat and its exact filenames are known. Remove those through the descriptor
        // opened when the directory was created; never recursively walk a pathname that another
        // same-uid process could have replaced with an unrelated directory.
        for name in self.names.iter().rev() {
            let _ = unlink_at(&self.directory, name);
        }
        let _ = self.directory.sync();
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| self.identity.matches(&metadata)) {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

/// An open directory used as the destination for `linkat`: replacing the directory pathname
/// after it is opened cannot redirect publication through a symlink or into another tree.
struct OpenDir(fs::File);

impl OpenDir {
    fn open(path: &Path) -> std::io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if !file.metadata()?.file_type().is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "migration path is not a directory",
            ));
        }
        Ok(Self(file))
    }

    fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    fn sync(&self) -> std::io::Result<()> {
        self.0.sync_all()
    }
}

fn c_name(name: &str) -> std::io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })
}

fn link_new(source: &OpenDir, destination: &OpenDir, name: &str) -> std::io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: both descriptors and the NUL-terminated name remain live for the call. Valid key
    // names contain no slash, and flags=0 creates a hard link without following a source symlink.
    let result = unsafe {
        libc::linkat(
            source.fd(),
            name.as_ptr(),
            destination.fd(),
            name.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unlink_at(directory: &OpenDir, name: &str) -> std::io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: `directory` and `name` remain valid for the syscall; names contain no slash.
    let result = unsafe { libc::unlinkat(directory.fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Collect the names of migratable key files in `old_store`, sorted for a
/// deterministic manifest. Skips dirs, dotfiles, and `keyring.json` (none of which
/// pass [`is_valid_key_name`], since `.` is rejected).
fn enumerate_keys(old_store: &Path) -> Result<Vec<String>, MigrateErr> {
    let mut names = Vec::new();
    for (at, entry) in fs::read_dir(old_store)?.enumerate() {
        if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy store has too many entries",
            )
            .into());
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue, // non-UTF-8 names can't be valid key names
        };
        if is_valid_key_name(&name) {
            if names.len() >= hc_core::MAX_STORE_FILES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "legacy store has too many keys",
                )
                .into());
            }
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Publish verified files without ever replacing an existing destination name. All links use
/// already-open directory descriptors. On an ordinary I/O failure, only links successfully
/// created by this invocation are removed, in reverse order.
fn publish_staged(
    staging: &StagingDir,
    new_store: &Path,
    migrated: &[MigratedKey],
) -> Result<(), MigrateErr> {
    let existed = destination_is_clear(new_store)?;
    let mut created_destination = false;
    if !existed {
        match fs::DirBuilder::new().mode(0o700).create(new_store) {
            Ok(()) => created_destination = true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(MigrateErr::NewStoreNotEmpty)
            }
            Err(error) => return Err(error.into()),
        }
    }

    let destination = match OpenDir::open(new_store) {
        Ok(directory) => directory,
        Err(error) => {
            if created_destination {
                let _ = fs::remove_dir(new_store);
            }
            return Err(error.into());
        }
    };
    let destination_identity = FileIdentity::of(&destination.0.metadata()?);

    // Pair the path-based bounded scan with the descriptor identity before linking. If the path
    // was swapped during either operation, fail closed; later linkat calls cannot be redirected.
    if !destination_is_clear(new_store)?
        || !fs::symlink_metadata(new_store)
            .is_ok_and(|metadata| destination_identity.matches(&metadata))
    {
        drop(destination);
        if created_destination
            && fs::symlink_metadata(new_store)
                .is_ok_and(|metadata| destination_identity.matches(&metadata))
        {
            let _ = fs::remove_dir(new_store);
        }
        return Err(MigrateErr::NewStoreNotEmpty);
    }

    let source = OpenDir::open(staging.path())?;
    let mut linked = Vec::with_capacity(migrated.len());
    let publication = (|| {
        for key in migrated {
            match link_new(&source, &destination, &key.name) {
                Ok(()) => linked.push(key.name.as_str()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(MigrateErr::NewStoreNotEmpty)
                }
                Err(error) => return Err(error.into()),
            }
        }
        destination.sync()?;
        OpenDir::open(store_parent(new_store)?)?.sync()?;

        // A rename of the destination cannot redirect descriptor-relative publication, but it
        // must not turn an otherwise-successful command into an invisible store elsewhere.
        if !fs::symlink_metadata(new_store)
            .is_ok_and(|metadata| destination_identity.matches(&metadata))
        {
            return Err(MigrateErr::NewStoreNotEmpty);
        }
        Ok(())
    })();

    if let Err(error) = publication {
        for name in linked.into_iter().rev() {
            let _ = unlink_at(&destination, name);
        }
        let _ = destination.sync();
        drop(destination);
        if created_destination
            && fs::symlink_metadata(new_store)
                .is_ok_and(|metadata| destination_identity.matches(&metadata))
        {
            // Never recurse here: if anybody inserted an unexpected entry, leave it intact.
            let _ = fs::remove_dir(new_store);
        }
        return Err(error);
    }
    Ok(())
}

/// Re-encrypt every legacy key in `old_store` under `dek` into `new_store`, verifying
/// each. `old_master` is the legacy Keychain master (fetched by the caller after Touch ID).
/// Keys named in `shareable` land [`KeyUse::Shareable`]; every other key lands
/// [`KeyUse::SignOnly`] and can never afterwards be exported.
///
/// Non-destructive and verify-before-finalize: keys are staged and fully verified
/// before `new_store` is created; on any error the staging dir is removed and
/// `old_store` is left untouched.
pub fn run(
    old_store: &Path,
    old_master: &[u8],
    new_store: &Path,
    dek: &Dek,
    shareable: &HashSet<String>,
) -> Result<Vec<MigratedKey>, MigrateErr> {
    let names = migration_plan(old_store, new_store, shareable)?;

    // Fresh, unpredictable staging dir on the same filesystem as `new_store`. It is created
    // exclusively; cleanup removes only the exact flat files this invocation recorded.
    let mut staging = StagingDir::create(new_store)?;

    // The RAII staging owner performs identity-checked cleanup on every return path.
    let migrated = stage_and_verify(old_store, old_master, &mut staging, dek, &names, shareable)?;

    // All verified. Each exact filename is a create-only link; a normal error rolls the batch
    // back, and no pre-existing regular file, symlink, or directory can be overwritten.
    publish_staged(&staging, new_store, &migrated)?;

    tracing::info!(count = migrated.len(), "migration finalized");
    Ok(migrated)
}

/// Validate every public filesystem fact before the CLI asks for either the legacy master or the
/// destination DEK. [`run`] repeats this check after authorization to close the time-of-check gap.
pub fn preflight(
    old_store: &Path,
    new_store: &Path,
    shareable: &HashSet<String>,
) -> Result<(), MigrateErr> {
    migration_plan(old_store, new_store, shareable).map(|_| ())
}

fn migration_plan(
    old_store: &Path,
    new_store: &Path,
    shareable: &HashSet<String>,
) -> Result<Vec<String>, MigrateErr> {
    destination_is_clear(new_store)?;
    let names = enumerate_keys(old_store)?;
    // A typo would silently seal a key its consumers still `/read`, and that is one-way.
    for name in shareable {
        if !names.contains(name) {
            return Err(MigrateErr::UnknownShareable { name: name.clone() });
        }
    }
    Ok(names)
}

/// Decrypt → record identity → re-encrypt → verify, for every name, into `staging`.
/// Returns the manifest on full success; the caller is responsible for cleaning up
/// `staging` if this returns `Err`.
fn stage_and_verify(
    old_store: &Path,
    old_master: &[u8],
    staging: &mut StagingDir,
    dek: &Dek,
    names: &[String],
    shareable: &HashSet<String>,
) -> Result<Vec<MigratedKey>, MigrateErr> {
    let mut migrated = Vec::with_capacity(names.len());
    for name in names {
        // a. Decrypt the legacy keystore (MAC-checked inside `decrypt_key`).
        let plaintext = hc_core::crypto::decrypt_key(old_store.join(name), old_master)?;

        // b. Record the public identity from the original bytes.
        let identity = derive_identity(&plaintext)?;

        // c. Re-seal under the new DEK into staging, binding the declared use.
        let key_use = if shareable.contains(name) {
            KeyUse::Shareable
        } else {
            KeyUse::SignOnly
        };
        encrypt_file(staging.path(), name, dek, key_use, &plaintext)?;
        staging.record(name);

        // d. Verify: round-trip the ciphertext AND re-derive the identity from the
        //    decrypted bytes; both must match before we trust this file.
        let roundtrip = decrypt_file(&staging.path().join(name), name, dek)?;
        let ok = roundtrip.as_slice() == plaintext.as_slice()
            && derive_identity(roundtrip.as_slice())? == identity;

        if !ok {
            return Err(MigrateErr::VerifyMismatch(name.clone()));
        }

        tracing::debug!(name = %name, %key_use, "key staged and verified");
        migrated.push(MigratedKey {
            name: name.clone(),
            identity,
            key_use,
        });
    }
    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::crypto::{encrypt_key, to_vec};

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

    fn staging_dirs(parent: &Path) -> Vec<PathBuf> {
        fs::read_dir(parent)
            .expect("read staging parent")
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                (name.starts_with(STAGING_PREFIX) && name.ends_with(STAGING_SUFFIX))
                    .then(|| entry.path())
            })
            .collect()
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
        let sol_bytes =
            hc_core::solana::generate_keypair(&mut rng).expect("generate Solana keypair");
        let sol_id = solana_address(&sol_bytes[..]).expect("derive Solana pubkey");
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

    /// `--shareable` names, as the CLI collects them.
    fn shareable(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn migrate_roundtrips_all_kinds_and_preserves_old_store() {
        let root = fresh_dir("happy");
        let (old_store, expected) = make_legacy_store(&root);
        let new_store = root.join("new_store");

        let before = snapshot(&old_store);
        let dek = Dek::random();
        let migrated = run(
            &old_store,
            PASSWORD.as_bytes(),
            &new_store,
            &dek,
            &shareable(&["EVM_KEY"]),
        )
        .expect("run ok");

        // Identities returned must match the directly-derived addresses, by name.
        assert_eq!(migrated.len(), expected.len());
        for (name, ident) in &expected {
            let got = migrated
                .iter()
                .find(|m| &m.name == name)
                .unwrap_or_else(|| panic!("missing migrated key {name}"));
            assert_eq!(&got.identity, ident, "identity mismatch for {name}");
            let want = if name == "EVM_KEY" {
                KeyUse::Shareable
            } else {
                KeyUse::SignOnly
            };
            assert_eq!(got.key_use, want, "use mismatch for {name}");
            let on_disk = hc_core::crypto::envelope::read_keystore(&new_store.join(name))
                .expect("migrated file parses");
            assert_eq!(on_disk.use_label(), want.label(), "header mismatch {name}");
        }

        // Each new file decrypts under the DEK back to the original legacy secret.
        for (name, _) in &expected {
            let migrated_secret =
                decrypt_file(&new_store.join(name), name, &dek).expect("decrypt new");
            let legacy_secret =
                hc_core::crypto::decrypt_key(old_store.join(name), PASSWORD).expect("decrypt old");
            assert_eq!(migrated_secret, legacy_secret, "secret changed for {name}");
        }

        // The decoy non-key file must NOT have been migrated.
        assert!(!new_store.join("keyring.json").exists());

        // old_store must be byte-identical afterwards.
        assert_eq!(before, snapshot(&old_store), "old_store was modified");

        // Staging dir must be gone.
        assert!(staging_dirs(&root).is_empty(), "staging not cleaned up");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_refuses_when_new_store_already_has_a_key() {
        let root = fresh_dir("nonempty");
        let (old_store, _) = make_legacy_store(&root);
        let new_store = root.join("new_store");
        fs::create_dir_all(&new_store).expect("mk new_store");
        // A pre-existing key file (valid name) must block migration.
        encrypt_file(
            &new_store,
            "EXISTING",
            &Dek::random(),
            KeyUse::SignOnly,
            b"squatter",
        )
        .expect("seed new");

        let dek = Dek::random();
        let res = run(
            &old_store,
            PASSWORD.as_bytes(),
            &new_store,
            &dek,
            &shareable(&[]),
        );
        assert!(matches!(res, Err(MigrateErr::NewStoreNotEmpty)));

        let _ = fs::remove_dir_all(&root);
    }

    /// Sealing is one-way, so a mistyped `--shareable` would quietly lock a key its consumers
    /// still read. It must abort before a single file is written.
    #[test]
    fn a_shareable_name_that_is_not_in_the_old_store_aborts() {
        let root = fresh_dir("unknown_shareable");
        let (old_store, _) = make_legacy_store(&root);
        let new_store = root.join("new_store");

        let res = run(
            &old_store,
            PASSWORD.as_bytes(),
            &new_store,
            &Dek::random(),
            &shareable(&["EVM_KEY", "EVM_KEYY"]),
        );
        assert!(matches!(res, Err(MigrateErr::UnknownShareable { name }) if name == "EVM_KEYY"));
        assert!(!new_store.exists());
        assert!(staging_dirs(&root).is_empty());

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
        let res = run(
            &old_store,
            PASSWORD.as_bytes(),
            &new_store,
            &dek,
            &shareable(&[]),
        );

        // It must abort (the corrupt file is not a valid keystore JSON / fails MAC).
        assert!(res.is_err(), "expected migration to abort on corrupt key");
        // No staging dir left behind.
        assert!(staging_dirs(&root).is_empty(), "staging dir leaked");
        // new_store must not have been created/populated.
        assert!(!new_store.join("SOLANA_KEY").exists());
        assert!(!new_store.join("RAW_KEY").exists());
        // old_store untouched (besides our own corruption).
        assert_eq!(before, snapshot(&old_store), "old_store was modified");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn migration_never_deletes_a_predictable_legacy_staging_path() {
        let root = fresh_dir("stale_staging");
        let (old_store, _) = make_legacy_store(&root);
        let new_store = root.join("new_store");
        let old_predictable = root.join("new_store.staging");
        fs::create_dir(&old_predictable).expect("create unrelated directory");
        fs::write(old_predictable.join("KEEP"), b"do not delete").expect("seed unrelated data");

        run(
            &old_store,
            PASSWORD.as_bytes(),
            &new_store,
            &Dek::random(),
            &shareable(&[]),
        )
        .expect("migration succeeds");

        assert_eq!(
            fs::read(old_predictable.join("KEEP")).expect("unrelated data survives"),
            b"do not delete"
        );
        assert!(staging_dirs(&root).is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn destination_symlink_at_a_key_name_is_never_replaced() {
        use std::os::unix::fs::symlink;

        let root = fresh_dir("destination_symlink");
        let (old_store, _) = make_legacy_store(&root);
        let new_store = root.join("new_store");
        fs::create_dir(&new_store).expect("create destination");
        let victim = root.join("victim");
        fs::write(&victim, b"untouched").expect("seed victim");
        symlink(&victim, new_store.join("EVM_KEY")).expect("plant destination symlink");

        let result = run(
            &old_store,
            PASSWORD.as_bytes(),
            &new_store,
            &Dek::random(),
            &shareable(&[]),
        );
        assert!(matches!(result, Err(MigrateErr::NewStoreNotEmpty)));
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert!(fs::symlink_metadata(new_store.join("EVM_KEY"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(staging_dirs(&root).is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn publication_error_rolls_back_links_created_by_this_run() {
        let root = fresh_dir("publish_rollback");
        let new_store = root.join("new_store");
        let mut staging = StagingDir::create(&new_store).expect("create staging");
        fs::write(staging.path().join("FIRST"), b"sealed bytes").expect("write first");
        staging.record("FIRST");
        let migrated = vec![
            MigratedKey {
                name: "FIRST".into(),
                identity: "one".into(),
                key_use: KeyUse::SignOnly,
            },
            MigratedKey {
                // Deliberately absent from staging so publication fails after FIRST linked.
                name: "SECOND".into(),
                identity: "two".into(),
                key_use: KeyUse::SignOnly,
            },
        ];

        assert!(publish_staged(&staging, &new_store, &migrated).is_err());
        assert!(!new_store.join("FIRST").exists());
        assert!(
            !new_store.exists(),
            "new destination dir should roll back when empty"
        );
        drop(staging);
        assert!(staging_dirs(&root).is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
