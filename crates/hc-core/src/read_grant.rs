//! Time-boxed, token-authenticated release of ONE shareable keystore.
//!
//! A grant is that keystore's plaintext sealed under a KEK derived from a fresh 256-bit token.
//! The token IS the key material: it is never written down, so the grant file alone is inert and
//! nothing here can show a token twice. Opening one needs neither the DEK nor the enclave, which
//! is what lets `/read` answer an agent with no human at the keyboard until the grant expires.
//!
//! The AAD binds the domain, the keystore name and the window, so a grant moved to another name
//! or given a later expiry on disk stops opening rather than covering more. Only an
//! [`ExportPermit`] mints one, so a [`crate::crypto::envelope::KeyUse::SignOnly`] key can never be
//! granted, and the refusal is read off the cleartext header before anything unlocks.
//!
//! A grant holds a COPY of the key, so what ends one has to be the key's LIVE state: [`open`]
//! re-reads the keystore's cleartext header on every release — no DEK, no enclave, no prompt —
//! and refuses unless that keystore still exists and still mints a permit. `seal --use sign-only`
//! and deleting the file therefore kill a live grant, which is what keeps `sign_only` a one-way
//! door for a key somebody was already handed a token for.
use crate::crypto::envelope::{
    open as aead_open, read_keystore, seal, write_private_file, Dek, EncFile, EnvErr, ExportPermit,
    KeystoreFile, MAX_KEYSTORE_FILE_BYTES,
};
use err_mac::create_err_with_impls;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The request header an agent presents its token in. Meaningful on `/read/<name>` and nowhere
/// else.
pub const GRANT_HEADER: &str = "x-hot-cheese-read-grant";

/// Hours a grant lasts when the operator names no window.
pub const DEFAULT_GRANT_HOURS: u32 = 48;

/// The longest window a grant may be given.
pub const MAX_GRANT_HOURS: u32 = 8760;

const GRANT_V1: u32 = 1;
const TOKEN_BYTES: usize = 32;
const SECONDS_PER_HOUR: u64 = 3600;
const KEK_INFO: &[u8] = b"hotcheese/read-grant/v1/kek";
const AAD_DOMAIN: &[u8] = b"hotcheese/read-grant/v1";

/// Base58 of 32 bytes is 44 characters; this bounds the decode work a presented token can cost.
const MAX_TOKEN_TEXT_BYTES: usize = 64;

create_err_with_impls!(
    #[derive(Debug)]
    pub ReadGrantErr,
    Kdf,
    Envelope(EnvErr),
    Base58(bs58::decode::Error),
    Serde(serde_json::Error),
    StdIo(std::io::Error)
    ;
    InvalidName { name: String },
    BadToken { len: usize },
    BadWindow { hours: u32, max: u32 },
    ClockOverflow { now: u64, hours: u32 },
    UnsafeDirectory { path: PathBuf },
    UnsupportedVersion { found: u32, expected: u32 },
    KeyMismatch { sealed: String, requested: String },
    Expired { expires_at: u64, now: u64 },
    NoSuchGrant { key: String },
    TooManyGrants { found: usize, max: usize }
);

/// A 256-bit bearer token: the only thing that opens a grant. Deliberately without `Debug`, so
/// no error, log line or panic can render one.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GrantToken([u8; TOKEN_BYTES]);

impl GrantToken {
    /// Fresh token from the OS CSPRNG, filled in place so no unwiped copy is left behind.
    pub fn random() -> Self {
        let mut token = Self([0u8; TOKEN_BYTES]);
        OsRng.fill_bytes(&mut token.0);
        token
    }

    /// Decode the base58 an operator handed to an agent.
    pub fn parse(text: &[u8]) -> Result<Self, ReadGrantErr> {
        if text.len() > MAX_TOKEN_TEXT_BYTES {
            return Err(ReadGrantErr::BadToken { len: text.len() });
        }
        let mut token = Self([0u8; TOKEN_BYTES]);
        let written = bs58::decode(text).onto(&mut token.0)?;
        if written != TOKEN_BYTES {
            return Err(ReadGrantErr::BadToken { len: written });
        }
        Ok(token)
    }

    /// The base58 rendering, which exists only for as long as the caller holds it.
    pub fn render(&self) -> Zeroizing<String> {
        Zeroizing::new(bs58::encode(&self.0).into_string())
    }

    fn kek(&self) -> Result<Zeroizing<[u8; 32]>, ReadGrantErr> {
        let mut kek = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(KEK_INFO, kek.as_mut())
            .map_err(|_| ReadGrantErr::Kdf)?;
        Ok(kek)
    }
}

/// One keystore's release, sealed under a token's KEK.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedGrant {
    /// Container version, always [`GRANT_V1`].
    v: u32,
    /// Keystore this grant releases.
    key: String,
    /// Unix seconds at which it was minted.
    issued_at: u64,
    /// Unix seconds at which the token stops working.
    expires_at: u64,
    /// The AEAD container holding the keystore's plaintext.
    body: EncFile,
}

/// Whether the keystore a grant names would still be released to whoever holds its token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The keystore is still there and still mints an export permit.
    Releases,
    /// The keystore is gone, or no longer shareable: the token releases nothing.
    Dead,
}

/// One live grant, as a listing shows it.
pub struct Live {
    /// Keystore this grant releases over `/read`.
    pub key: String,
    /// Unix seconds at which the token stops working.
    pub expires_at: u64,
    /// Seconds left before it does.
    pub remaining_secs: u64,
    /// Whether the key it names would still be released.
    pub standing: Standing,
}

impl fmt::Display for Live {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} expires {} ({}h {}m left){}",
            self.key,
            utc(self.expires_at),
            self.remaining_secs / SECONDS_PER_HOUR,
            (self.remaining_secs % SECONDS_PER_HOUR) / 60,
            match self.standing {
                Standing::Releases => "",
                Standing::Dead => " — DEAD: its keystore is gone or no longer shareable",
            }
        )
    }
}

/// A grant that has just been minted.
pub struct Granted {
    /// The bearer token, shown once and stored nowhere.
    pub token: GrantToken,
    /// The key, the expiry and the time it has left.
    pub live: Live,
    /// Whether this replaced an earlier grant, whose token stopped working.
    pub replaced: bool,
}

/// `DOMAIN ‖ 0x00 ‖ name ‖ 0x00 ‖ issue ‖ expiry`, unambiguous because a key name is
/// `[A-Za-z0-9_]` and both timestamps are fixed length.
fn grant_aad(name: &str, issued_at: u64, expires_at: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + name.len() + 18);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&issued_at.to_be_bytes());
    aad.extend_from_slice(&expires_at.to_be_bytes());
    aad
}

fn grant_path(dir: &Path, name: &str) -> Result<PathBuf, ReadGrantErr> {
    if !crate::is_valid_key_name(name) {
        return Err(ReadGrantErr::InvalidName {
            name: name.to_string(),
        });
    }
    Ok(dir.join(name))
}

/// Read one grant's cleartext container and refuse it if it is not this version, not this key, or
/// out of time. An expired grant's file is removed before the refusal, so time alone clears it —
/// but only while `now` is within one window of the expiry. A clock that has moved further past
/// it than the grant's whole life is not evidence the grant is over, and unlinking the operator's
/// live grants because the machine's clock jumped is data loss the refusal does not need.
fn load(path: &Path, name: &str, now: u64) -> Result<SealedGrant, ReadGrantErr> {
    let bytes = crate::read_private_file_bounded(path, MAX_KEYSTORE_FILE_BYTES)?;
    let grant: SealedGrant = crate::wire::strict_json_from_slice(&bytes)?;
    if grant.v != GRANT_V1 {
        return Err(ReadGrantErr::UnsupportedVersion {
            found: grant.v,
            expected: GRANT_V1,
        });
    }
    if grant.key != name {
        return Err(ReadGrantErr::KeyMismatch {
            sealed: grant.key,
            requested: name.to_string(),
        });
    }
    if grant.expires_at <= now {
        if now.saturating_sub(grant.expires_at) <= grant.expires_at.saturating_sub(grant.issued_at)
        {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        return Err(ReadGrantErr::Expired {
            expires_at: grant.expires_at,
            now,
        });
    }
    Ok(grant)
}

/// Unix seconds a grant minted at `now` stops working, refusing a window of zero hours or one
/// past [`MAX_GRANT_HOURS`]. Every surface that mints a grant calls this BEFORE it unlocks
/// anything: a window argument that cannot be granted must never cost a biometric.
pub fn expiry_at(now: u64, hours: u32) -> Result<u64, ReadGrantErr> {
    if hours == 0 || hours > MAX_GRANT_HOURS {
        return Err(ReadGrantErr::BadWindow {
            hours,
            max: MAX_GRANT_HOURS,
        });
    }
    u64::from(hours)
        .checked_mul(SECONDS_PER_HOUR)
        .and_then(|window| now.checked_add(window))
        .ok_or(ReadGrantErr::ClockOverflow { now, hours })
}

/// Seal the permitted key under a fresh token and write the grant 0600 inside a 0700 `dir`. The
/// permit is the only way in, and it exists only for a keystore sealed shareable. The directory
/// is proven to be a directory this uid owns before its mode is forced, so the chmod cannot be
/// aimed at anything else through a symlink standing where the grants live.
pub fn create(
    dir: &Path,
    name: &str,
    permit: ExportPermit,
    dek: &Dek,
    now: u64,
    hours: u32,
) -> Result<Granted, ReadGrantErr> {
    let expires_at = expiry_at(now, hours)?;
    let path = grant_path(dir, name)?;
    let secret = permit.open(name, dek)?;
    let token = GrantToken::random();
    let kek = token.kek()?;
    let grant = SealedGrant {
        v: GRANT_V1,
        key: name.to_string(),
        issued_at: now,
        expires_at,
        body: seal(&kek, &grant_aad(name, now, expires_at), &secret)?,
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let holding = std::fs::symlink_metadata(dir)?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if !holding.file_type().is_dir() || holding.uid() != ours {
        return Err(ReadGrantErr::UnsafeDirectory {
            path: dir.to_path_buf(),
        });
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let replaced = std::fs::symlink_metadata(&path).is_ok();
    write_private_file(&path, &serde_json::to_vec(&grant)?)?;
    Ok(Granted {
        token,
        live: Live {
            key: name.to_string(),
            expires_at,
            remaining_secs: expires_at.saturating_sub(now),
            standing: Standing::Releases,
        },
        replaced,
    })
}

/// Release `name`'s key to a caller presenting `token`, provided `store` still holds that
/// keystore and its cleartext header still mints an export permit. Touches no DEK and no enclave:
/// a tightened key, a deleted one and a wrong token all fail here, and a wrong token simply fails
/// the AEAD, so there is no comparison to time and nothing to farm.
pub fn open(
    grants: &Path,
    store: &Path,
    name: &str,
    token: &GrantToken,
    now: u64,
) -> Result<Zeroizing<Vec<u8>>, ReadGrantErr> {
    let path = grant_path(grants, name)?;
    read_keystore(&store.join(name))?.export_permit()?;
    let grant = load(&path, name, now)?;
    let kek = token.kek()?;
    Ok(aead_open(
        &kek,
        &grant_aad(name, grant.issued_at, grant.expires_at),
        &grant.body,
    )?)
}

/// Every grant still in force, soonest expiry first, each with whether the key it names would
/// still be released. Expired ones are dropped, and removed on [`load`]'s terms.
pub fn list(dir: &Path, store: &Path, now: u64) -> Result<Vec<Live>, ReadGrantErr> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut live = Vec::new();
    for (at, entry) in entries.enumerate() {
        if at >= crate::MAX_STORE_ENUM_ENTRIES {
            return Err(ReadGrantErr::TooManyGrants {
                found: at,
                max: crate::MAX_STORE_ENUM_ENTRIES,
            });
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !crate::is_valid_key_name(&name) {
            continue;
        }
        match load(&grant_path(dir, &name)?, &name, now) {
            Ok(grant) => live.push(Live {
                key: grant.key,
                expires_at: grant.expires_at,
                remaining_secs: grant.expires_at.saturating_sub(now),
                standing: match read_keystore(&store.join(&name))
                    .and_then(KeystoreFile::export_permit)
                {
                    Ok(_) => Standing::Releases,
                    Err(_) => Standing::Dead,
                },
            }),
            Err(ReadGrantErr::Expired { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    live.sort_by(|a, b| a.expires_at.cmp(&b.expires_at).then(a.key.cmp(&b.key)));
    Ok(live)
}

/// Destroy one grant now.
pub fn revoke(dir: &Path, name: &str) -> Result<(), ReadGrantErr> {
    let path = grant_path(dir, name)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(ReadGrantErr::NoSuchGrant {
                key: name.to_string(),
            })
        }
        Err(error) => Err(error.into()),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp, on the proleptic Gregorian calendar.
fn utc(at: u64) -> String {
    let days = at / 86_400;
    let seconds = at % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 { shifted + 3 } else { shifted - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / SECONDS_PER_HOUR,
        (seconds % SECONDS_PER_HOUR) / 60,
        seconds % 60
    )
}

/// The block an operator hands to an agent: what it may read, until when, and how to ask. It
/// carries the token, so it is wiped with the caller that printed it.
pub fn handoff(granted: &Granted, port: u16) -> Zeroizing<String> {
    let rendered = granted.token.render();
    let token = rendered.as_str();
    let live = &granted.live;
    let key = &live.key;
    let expiry = utc(live.expires_at);
    Zeroizing::new(format!(
        "hot_cheese read grant — shown once, stored nowhere\n\
         grant     {live}\n\
         token     {token}\n\
         \n\
         Paste from here down to the agent:\n\
         \n\
         hot_cheese will hand you the key \"{key}\" with no Touch ID until {expiry}.\n\
         The reference client is crates/hc-daemon/examples/pin_cert.rs, which reads the\n\
         token out of the environment and presents it for you:\n\
         \n\
           export HOT_CHEESE_READ_GRANT={token}\n\
           cargo run --release --example pin_cert -- https://localhost:{port} {key}\n\
         \n\
         From your own consumer, POST the ephemeral-key handshake\n\
         {{\"pubk\":\"0x04<65-byte SEC1 P-256 public key>\"}} to\n\
         https://localhost:{port}/read/{key} with the headers\n\
         content-type: application/json\n\
         {GRANT_HEADER}: {token}\n\
         and decrypt the answer with the matching private key. The token opens that one\n\
         key on that one route and nothing else, and only while \"{key}\" is still sealed\n\
         shareable: `seal --use sign-only` ends this grant on the spot."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope::{encrypt_file, read_keystore, KeyUse};

    const SHAREABLE: &str = "SOLVER";
    const LOCKED: &str = "TREASURY";
    const SECRET: &[u8; 32] = &[0x5au8; 32];
    const NOW: u64 = 1_700_000_000;

    struct Fixture {
        root: std::path::PathBuf,
        store: std::path::PathBuf,
        grants: std::path::PathBuf,
        dek: Dek,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "hot_cheese_read_grant_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("the test host's clock is after the epoch")
                    .as_nanos()
            ));
            let store = root.join("store");
            std::fs::create_dir_all(&store).expect("make the store");
            let dek = Dek::from_bytes([9u8; 32]);
            encrypt_file(&store, SHAREABLE, &dek, KeyUse::Shareable, SECRET).expect("seal");
            encrypt_file(&store, LOCKED, &dek, KeyUse::SignOnly, SECRET).expect("seal");
            Self {
                grants: root.join("read-grants"),
                root,
                store,
                dek,
            }
        }

        fn permit(&self, name: &str) -> Result<ExportPermit, EnvErr> {
            read_keystore(&self.store.join(name))?.export_permit()
        }

        fn grant(&self, hours: u32) -> Granted {
            create(
                &self.grants,
                SHAREABLE,
                self.permit(SHAREABLE).expect("shareable mints a permit"),
                &self.dek,
                NOW,
                hours,
            )
            .expect("create the grant")
        }

        fn released(
            &self,
            token: &GrantToken,
            now: u64,
        ) -> Result<Zeroizing<Vec<u8>>, ReadGrantErr> {
            open(&self.grants, &self.store, SHAREABLE, token, now)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777
    }

    /// A key sealed sign_only mints no export permit, so nothing can reach `create` for it and
    /// no grant file appears; the shareable key in the same store is what proves the refusal is
    /// the header's doing and not a store that cannot answer.
    #[test]
    fn a_sign_only_key_can_never_be_granted() {
        let fixture = Fixture::new("sign_only");
        assert!(matches!(
            fixture.permit(LOCKED),
            Err(EnvErr::ExportRefused {
                key_use: KeyUse::SignOnly
            })
        ));
        assert!(!fixture.grants.exists());

        let granted = fixture.grant(DEFAULT_GRANT_HOURS);
        assert!(!granted.replaced);
        assert_eq!(mode(&fixture.grants), 0o700);
        assert_eq!(mode(&fixture.grants.join(SHAREABLE)), 0o600);
        assert!(!fixture.grants.join(LOCKED).exists());
    }

    /// The token an operator pastes is the base58 text, and it alone releases the key: the DEK
    /// that sealed the keystore is not consulted, which is the whole point of a grant.
    #[test]
    fn the_pasted_token_alone_releases_the_key() {
        let fixture = Fixture::new("release");
        let granted = fixture.grant(DEFAULT_GRANT_HOURS);
        let pasted = granted.token.render();
        let token = GrantToken::parse(pasted.as_bytes()).expect("the printed token parses back");
        assert_eq!(
            fixture.released(&token, NOW).expect("open").as_slice(),
            SECRET
        );
        assert_eq!(granted.live.remaining_secs, 48 * 3600);
    }

    /// A grant is a COPY of the key, so the only thing that can end one early is the key's live
    /// state: tightening the keystore to sign_only and deleting it outright must each stop a
    /// token that was releasing the key seconds earlier, without a DEK, an unlock or a prompt —
    /// and both must refuse exactly as a wrong token does, so no failure here reads back as a
    /// probe of what the store holds.
    #[test]
    fn a_live_grant_dies_with_the_key_it_names() {
        let fixture = Fixture::new("tightened");
        let granted = fixture.grant(DEFAULT_GRANT_HOURS);
        assert_eq!(
            fixture
                .released(&granted.token, NOW)
                .expect("the grant releases while the key is shareable")
                .as_slice(),
            SECRET
        );

        encrypt_file(
            &fixture.store,
            SHAREABLE,
            &fixture.dek,
            KeyUse::SignOnly,
            SECRET,
        )
        .expect("seal the key sign_only");
        assert!(matches!(
            fixture.released(&granted.token, NOW),
            Err(ReadGrantErr::Envelope(EnvErr::ExportRefused {
                key_use: KeyUse::SignOnly
            }))
        ));
        assert!(
            fixture.grants.join(SHAREABLE).exists(),
            "the refusal is the key's live header, not a file this path may delete"
        );

        std::fs::remove_file(fixture.store.join(SHAREABLE)).expect("delete the keystore");
        assert!(matches!(
            fixture.released(&granted.token, NOW),
            Err(ReadGrantErr::Envelope(EnvErr::StdIo(_)))
        ));

        let listed = list(&fixture.grants, &fixture.store, NOW).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].standing, Standing::Dead);
        assert!(
            listed[0].to_string().contains("DEAD"),
            "the operator must be told a grant releases nothing: {}",
            listed[0]
        );
    }

    /// A token that does not open the grant and a key with no grant at all are both refusals,
    /// so an attacker spraying tokens learns nothing and reaches no prompt either way.
    #[test]
    fn a_wrong_token_and_an_absent_grant_both_refuse() {
        let fixture = Fixture::new("wrong");
        let granted = fixture.grant(DEFAULT_GRANT_HOURS);
        assert!(matches!(
            fixture.released(&GrantToken::random(), NOW),
            Err(ReadGrantErr::Envelope(EnvErr::Aead))
        ));
        assert!(open(&fixture.grants, &fixture.store, LOCKED, &granted.token, NOW).is_err());
        assert!(matches!(
            GrantToken::parse(b"not base58 at all"),
            Err(ReadGrantErr::Base58(_))
        ));
        assert!(matches!(
            GrantToken::parse("1".repeat(MAX_TOKEN_TEXT_BYTES + 1).as_bytes()),
            Err(ReadGrantErr::BadToken {
                len
            }) if len == MAX_TOKEN_TEXT_BYTES + 1
        ));
        assert!(matches!(
            GrantToken::parse("1".repeat(TOKEN_BYTES - 1).as_bytes()),
            Err(ReadGrantErr::BadToken {
                len
            }) if len == TOKEN_BYTES - 1
        ));
        assert!(matches!(
            GrantToken::parse("1".repeat(TOKEN_BYTES + 1).as_bytes()),
            Err(ReadGrantErr::Base58(bs58::decode::Error::BufferTooSmall))
        ));
        assert!(matches!(
            GrantToken::parse(granted.token.render().as_bytes())
                .map(|token| fixture.released(&token, NOW)),
            Ok(Ok(_))
        ));
    }

    /// The expiry is in the AAD, so editing it on disk to buy more time yields a grant that
    /// opens for nobody instead of one that lasts longer.
    #[test]
    fn editing_the_expiry_on_disk_destroys_the_grant() {
        let fixture = Fixture::new("tamper");
        let granted = fixture.grant(1);
        let path = fixture.grants.join(SHAREABLE);
        let honest = std::fs::read_to_string(&path).expect("read the grant");
        let stamped = format!("\"expires_at\":{}", granted.live.expires_at);
        assert!(honest.contains(&stamped), "{honest}");
        let forged = honest.replace(&stamped, "\"expires_at\":9000000000");
        std::fs::write(&path, &forged).expect("forge the expiry");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        assert!(matches!(
            fixture.released(&granted.token, NOW),
            Err(ReadGrantErr::Envelope(EnvErr::Aead))
        ));
        let listed = list(&fixture.grants, &fixture.store, NOW).expect("list");
        assert_eq!(listed.len(), 1, "the header now lies about its expiry");
        assert_eq!(listed[0].expires_at, 9_000_000_000);
    }

    /// Time alone ends a grant: past the expiry it is refused and its file is gone, so a token
    /// that leaked after the window stops mattering without anyone running a command.
    #[test]
    fn an_expired_grant_is_refused_and_removed() {
        let fixture = Fixture::new("expired");
        let granted = fixture.grant(1);
        let path = fixture.grants.join(SHAREABLE);
        assert_eq!(
            list(&fixture.grants, &fixture.store, NOW)
                .expect("list")
                .len(),
            1
        );

        assert!(matches!(
            fixture.released(&granted.token, NOW + 3600),
            Err(ReadGrantErr::Expired {
                expires_at,
                now
            }) if expires_at == NOW + 3600 && now == NOW + 3600
        ));
        assert!(!path.exists());
        assert!(list(&fixture.grants, &fixture.store, NOW)
            .expect("list")
            .is_empty());
    }

    /// A clock that jumps forward is not a grant that ended. Past the expiry the token is refused
    /// either way, but a `now` further past it than the grant's whole window is treated as a
    /// clock nobody should destroy the operator's grants on: the file survives, and once the
    /// clock is right the grant releases again.
    #[test]
    fn a_forward_clock_jump_refuses_without_destroying_the_grant() {
        let fixture = Fixture::new("jump");
        let granted = fixture.grant(1);
        let path = fixture.grants.join(SHAREABLE);

        assert!(matches!(
            fixture.released(&granted.token, NOW + 365 * 86_400),
            Err(ReadGrantErr::Expired { .. })
        ));
        assert!(path.exists(), "a jumped clock must not unlink a live grant");
        assert!(
            list(&fixture.grants, &fixture.store, NOW + 365 * 86_400)
                .expect("list")
                .is_empty(),
            "and it must still refuse to serve while the clock says so"
        );

        assert_eq!(
            fixture
                .released(&granted.token, NOW)
                .expect("the corrected clock finds the grant intact")
                .as_slice(),
            SECRET
        );
    }

    /// Re-granting a key rotates the token, which is what silently ends the previous agent's
    /// access; revoking one ends it now, and revoking nothing is an error rather than a shrug.
    #[test]
    fn regranting_rotates_and_revoking_ends_a_grant() {
        let fixture = Fixture::new("rotate");
        let first = fixture.grant(DEFAULT_GRANT_HOURS);
        let second = fixture.grant(DEFAULT_GRANT_HOURS);
        assert!(second.replaced);
        assert!(matches!(
            fixture.released(&first.token, NOW),
            Err(ReadGrantErr::Envelope(EnvErr::Aead))
        ));

        revoke(&fixture.grants, SHAREABLE).expect("revoke");
        assert!(fixture.released(&second.token, NOW).is_err());
        assert!(matches!(
            revoke(&fixture.grants, SHAREABLE),
            Err(ReadGrantErr::NoSuchGrant { .. })
        ));
        assert!(matches!(
            revoke(&fixture.grants, "../escape"),
            Err(ReadGrantErr::InvalidName { .. })
        ));
    }

    /// The calendar the expiry is shown on: the epoch, a century leap year, a leap day, and a
    /// value with a time of day, all rendered without a date library.
    #[test]
    fn utc_renders_the_gregorian_calendar() {
        for (at, rendered) in [
            (0u64, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (4_107_542_399, "2100-02-28T23:59:59Z"),
        ] {
            assert_eq!(utc(at), rendered, "{at}");
        }
    }

    /// A window of zero hours, or one past the ceiling, is a mistake rather than a grant — and
    /// [`expiry_at`] refuses it on its own, which is what lets every front end decide it before
    /// it asks the operator for a fingerprint.
    #[test]
    fn a_window_outside_the_allowed_range_mints_nothing() {
        let fixture = Fixture::new("window");
        for hours in [0, MAX_GRANT_HOURS + 1] {
            assert!(matches!(
                expiry_at(NOW, hours),
                Err(ReadGrantErr::BadWindow { .. })
            ));
            assert!(matches!(
                create(
                    &fixture.grants,
                    SHAREABLE,
                    fixture.permit(SHAREABLE).expect("permit"),
                    &fixture.dek,
                    NOW,
                    hours,
                ),
                Err(ReadGrantErr::BadWindow { .. })
            ));
        }
        assert!(matches!(
            expiry_at(u64::MAX, MAX_GRANT_HOURS),
            Err(ReadGrantErr::ClockOverflow { .. })
        ));
        assert_eq!(expiry_at(NOW, 1).expect("an hour is a window"), NOW + 3600);
        assert!(!fixture.grants.exists());
    }

    /// The grants directory is chmodded to 0700 on every mint, so it must be proven to BE a
    /// directory this uid owns first: a symlink standing where the grants live would otherwise
    /// aim that chmod at whatever it points to.
    #[test]
    fn a_symlink_where_the_grants_live_is_never_chmodded_through() {
        let fixture = Fixture::new("dirlink");
        let elsewhere = fixture.root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("make the directory it points to");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the directory it points to");
        std::os::unix::fs::symlink(&elsewhere, &fixture.grants).expect("plant the link");

        assert!(matches!(
            create(
                &fixture.grants,
                SHAREABLE,
                fixture.permit(SHAREABLE).expect("permit"),
                &fixture.dek,
                NOW,
                1,
            ),
            Err(ReadGrantErr::UnsafeDirectory { .. })
        ));
        assert_eq!(mode(&elsewhere), 0o755);
        assert!(!elsewhere.join(SHAREABLE).exists());
    }
}
