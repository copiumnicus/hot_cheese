//! SSH bootstrap ritual: move the DEK from authority machine A to new machine B.
//!
//! A new machine B obtains the Data Encryption Key (DEK) from an authority machine
//! A over an SSH pipe, using ECIES so the DEK NEVER crosses the wire in plaintext.
//!
//! # Transport
//! `bootstrap_from(target)` spawns `ssh <target> hot_cheese bootstrap-serve` and
//! speaks a length-prefixed frame protocol over the child's piped stdin/stdout.
//! `bootstrap_serve()` is the far end of that SSH command: it speaks the SAME
//! protocol over its OWN process stdin/stdout. No new network listener is opened —
//! we reuse SSH purely as an authenticated, encrypted byte pipe.
//!
//! # Roles
//! - **B** (`bootstrap_from`) is the client: it has a Secure Enclave (SE) key and
//!   wants the DEK delivered sealed to that key.
//! - **A** (`bootstrap_serve`) is the authority: it already holds the DEK (wrapped
//!   in its keyring) and authorizes the transfer with a live Touch ID on A.
//!
//! # Cryptographic core (ephemeral-static ECIES to B's SE key)
//! 1. B sends its SE public key `b_se_pub` (65-byte uncompressed SEC1).
//! 2. A generates an EPHEMERAL P-256 keypair `E`, computes
//!    `shared = ECDH(E_priv, b_se_pub)` and `wrapKey = HKDF-SHA256(shared, INFO)`.
//! 3. A seals the DEK: `enc_dek = AEAD_seal(wrapKey, aad = b_se_pub ++ E_pub, dek)`
//!    and sends `E_pub` + `enc_dek`. The DEK on the wire is ciphertext only.
//! 4. B recomputes `shared = ECDH(SE_priv, E_pub)` (Touch ID on B), derives the same
//!    `wrapKey`, and opens `enc_dek` with `aad = b_se_pub ++ E_pub`.
//!
//! Ephemeral-static ECDH gives DEK confidentiality and forward secrecy even if the
//! transport is fully compromised: an attacker who records the stream cannot recover
//! the DEK without B's SE private key (which never leaves the enclave). The AAD
//! `b_se_pub ++ E_pub` binds the sealed DEK to BOTH endpoints, so a recorded `OFFER`
//! cannot be relayed to a different B or replayed under a different ephemeral key.
//!
//! # Residual trust assumptions
//! - **A's host identity / channel auth comes from SSH** (known_hosts / TOFU). We do
//!   NOT add a second authentication layer: if you trust `ssh <target>` to reach the
//!   real A, you trust this bootstrap. A MITM that can fully impersonate A over SSH
//!   could serve a DEK of its choosing — but it still cannot LEARN B's DEK, because
//!   confidentiality rests on B's SE key, not on the channel. Verify the SSH host key
//!   fingerprint out-of-band before first connect.
//! - **A authorizes the transfer with Touch ID on A's physical machine.** Because
//!   A's stdin/stdout are consumed by this protocol, A cannot prompt for an
//!   interactive recovery passphrase; the supported authority path is therefore a
//!   Secure Enclave enrollment on A (see [`select_authority_unlocker`]).
//! - **B re-wraps under its OWN keys.** A's keyring enrollments (A's `se_pub` /
//!   stored `eph_pub`) are device-bound and meaningless on B, so B builds a FRESH
//!   keyring enrolling the DEK under B's SE (and, if `HOT_CHEESE_BOOTSTRAP_PASSPHRASE`
//!   is set, a recovery passphrase). A's `keyring.json` is never copied.
//! - The plaintext DEK exists transiently in A's and B's process memory during the
//!   ritual; it is zeroized as soon as it is no longer needed.
use crate::config::Config;
use crate::crypto::envelope::{self, Dek, EncFile};
use crate::keyring::Keyring;
use crate::mac::secure_enclave;
use crate::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, Unlocker};
use err_mac::create_err_with_impls;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Keychain label for this host's Secure Enclave bootstrap key. Stable per machine.
const LABEL: &str = crate::mac::secure_enclave::SE_KEY_LABEL;
/// Protocol version carried in `HELLO` and checked by A.
const PROTO: u32 = 1;
/// HKDF `info` string — domain-separates this wrap key from any other ECDH use.
const HKDF_INFO: &[u8] = b"hotcheese/bootstrap/v1";
/// Uncompressed SEC1 P-256 public key length (`0x04 || X || Y`).
const SEC1_LEN: usize = 65;
/// Hard cap on a single frame payload (defends the reader against a hostile peer
/// claiming a huge length). Keystore files are tiny; 16 MiB is generous.
const MAX_FRAME: u32 = 16 * 1024 * 1024;
/// Env var: if set, B also enrolls a recovery passphrase from this value so the
/// restored envelope survives loss of B's Secure Enclave key.
const PASSPHRASE_ENV: &str = "HOT_CHEESE_BOOTSTRAP_PASSPHRASE";
/// Touch ID sheet text for B's enclave ECDH that opens the DEK sealed by the authority.
const ECDH_REASON: &str = "Unlock this machine's hot_cheese enclave key for bootstrap";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Variant meanings (the macro does not accept per-variant doc comments):
//   Protocol       frame/handshake violation (bad tag order, truncation, oversize)
//   ProtoMismatch  peer reported a version we do not speak
//   BadPubKey      a wire public key was not a valid 65-byte uncompressed SEC1 point
//   PeerAbort      the peer sent an ERROR frame (message logged, not retained typed)
//   NoSeAuthority  A has no Secure Enclave enrollment, so it cannot authorize headless
//   DekOpenFailed  sealed-DEK AEAD open failed (wrong key / tamper / relay); nothing saved
//   Ssh            the ssh child could not be spawned or exited non-zero
create_err_with_impls!(
    #[derive(Debug)]
    pub BootstrapErr,
    Protocol,
    ProtoMismatch,
    BadPubKey,
    PeerAbort,
    NoSeAuthority,
    DekOpenFailed,
    Ssh,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Config(crate::config::ConfigErr),
    Keyring(crate::keyring::KeyringErr),
    Unlock(crate::unlock::UnlockErr),
    Envelope(crate::crypto::envelope::EnvErr),
    Se(crate::mac::secure_enclave::SeErr),
    P256(p256::elliptic_curve::Error)
    ;
);

// ---------------------------------------------------------------------------
// ECDH abstraction (decoupled from the Secure Enclave for testing)
// ---------------------------------------------------------------------------

/// "Do an ECDH using MY private key against a peer's public key", abstracted over
/// where the private key lives. This is the single seam that lets the full handshake
/// run in tests with software P-256 keys standing in for both SE endpoints, while
/// production uses the Touch-ID-gated Secure Enclave.
pub enum EcdhKey {
    /// Private key held in the Secure Enclave under this keychain label. Each
    /// [`EcdhKey::ecdh`] call triggers Touch ID via [`secure_enclave::se_ecdh`].
    SecureEnclave(String),
    /// Software P-256 private key (tests, and authority machines without an SE).
    /// The held [`SecretKey`] is zeroized on drop by `p256`.
    Software(SecretKey),
}

impl EcdhKey {
    /// This key's public point as 65-byte uncompressed SEC1 (`0x04 || X || Y`).
    fn public_sec1(&self) -> Result<Vec<u8>, BootstrapErr> {
        match self {
            EcdhKey::SecureEnclave(label) => Ok(secure_enclave::se_public_key(label)?),
            EcdhKey::Software(sk) => {
                // p256's NistP256 sets COMPRESS_POINTS = false, so this is uncompressed 65B.
                Ok(sk.public_key().to_sec1_bytes().into_vec())
            }
        }
    }

    /// 32-byte ECDH shared secret (the X-coordinate) against `peer_sec1`.
    /// Zeroized on drop. For the SE variant this requires a live Touch ID.
    fn ecdh(&self, peer_sec1: &[u8]) -> Result<Zeroizing<[u8; 32]>, BootstrapErr> {
        match self {
            EcdhKey::SecureEnclave(label) => Ok(secure_enclave::se_ecdh(
                label,
                peer_sec1,
                None,
                ECDH_REASON,
            )?),
            EcdhKey::Software(sk) => {
                let peer = PublicKey::from_sec1_bytes(peer_sec1)?;
                let shared = diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                let bytes = shared.raw_secret_bytes();
                let mut out = [0u8; 32];
                out.copy_from_slice(bytes.as_slice());
                Ok(Zeroizing::new(out))
            }
        }
    }
}

/// `wrapKey = HKDF-SHA256(ikm = shared, info = HKDF_INFO)`. Zeroized on drop.
fn derive_wrap_key(shared: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, BootstrapErr> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut_slice())
        .map_err(|_| BootstrapErr::Protocol)?;
    Ok(out)
}

/// AAD binding the sealed DEK to both endpoints: `b_se_pub ++ E_pub`.
fn bind_aad(b_se_pub: &[u8], eph_pub: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(b_se_pub.len() + eph_pub.len());
    aad.extend_from_slice(b_se_pub);
    aad.extend_from_slice(eph_pub);
    aad
}

fn check_sec1(b: &[u8]) -> Result<(), BootstrapErr> {
    if b.len() == SEC1_LEN && b[0] == 0x04 {
        Ok(())
    } else {
        Err(BootstrapErr::BadPubKey)
    }
}

// ---------------------------------------------------------------------------
// Frame protocol: [u32 BE length][1 byte tag][JSON payload]
// `length` covers the tag byte plus the JSON payload.
// ---------------------------------------------------------------------------

/// Frame type tags. The wire order for a successful run is:
/// `HELLO → OFFER → FILE* → DONE → ACK`. Either side may send `ERROR` to abort.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Tag {
    Hello = 1,
    Offer = 2,
    File = 3,
    Done = 4,
    Ack = 5,
    Error = 6,
}

impl Tag {
    fn from_u8(b: u8) -> Result<Self, BootstrapErr> {
        match b {
            1 => Ok(Tag::Hello),
            2 => Ok(Tag::Offer),
            3 => Ok(Tag::File),
            4 => Ok(Tag::Done),
            5 => Ok(Tag::Ack),
            6 => Ok(Tag::Error),
            _ => Err(BootstrapErr::Protocol),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Hello {
    proto: u32,
    #[serde(with = "hex::serde")]
    b_se_pub: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Offer {
    #[serde(with = "hex::serde")]
    eph_pub: Vec<u8>,
    enc_dek: EncFile,
    /// Names of the keystore files that will follow as `FILE` frames.
    manifest: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct FileMsg {
    name: String,
    /// Raw on-disk bytes of the keystore `EncFile` JSON, shipped verbatim.
    #[serde(with = "hex::serde")]
    body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Done {
    count: u32,
}

#[derive(Serialize, Deserialize)]
struct Ack {
    ok: bool,
}

#[derive(Serialize, Deserialize)]
struct ErrorMsg {
    msg: String,
}

/// Serialize `payload` as JSON and write one framed message.
fn write_frame<W: Write, T: Serialize>(
    w: &mut W,
    tag: Tag,
    payload: &T,
) -> Result<(), BootstrapErr> {
    let body = serde_json::to_vec(payload)?;
    let len = (body.len() as u64) + 1; // +1 tag byte
    if len > MAX_FRAME as u64 {
        return Err(BootstrapErr::Protocol);
    }
    w.write_all(&(len as u32).to_be_bytes())?;
    w.write_all(&[tag as u8])?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one framed message: returns its tag and the raw JSON payload bytes.
fn read_frame<R: Read>(r: &mut R) -> Result<(Tag, Vec<u8>), BootstrapErr> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME {
        return Err(BootstrapErr::Protocol);
    }
    let mut tag_buf = [0u8; 1];
    r.read_exact(&mut tag_buf)?;
    let tag = Tag::from_u8(tag_buf[0])?;
    let mut body = vec![0u8; (len - 1) as usize];
    r.read_exact(&mut body)?;
    Ok((tag, body))
}

/// Read a frame, decode its JSON payload, and assert it carries `expect`.
/// If the peer sent an `ERROR`, surface it as [`BootstrapErr::PeerAbort`].
fn read_expect<R: Read, T: DeserializeOwned>(r: &mut R, expect: Tag) -> Result<T, BootstrapErr> {
    let (tag, body) = read_frame(r)?;
    if tag == Tag::Error {
        let e: ErrorMsg = serde_json::from_slice(&body)?;
        tracing::error!(peer_msg = %e.msg, "bootstrap peer aborted");
        return Err(BootstrapErr::PeerAbort);
    }
    if tag != expect {
        return Err(BootstrapErr::Protocol);
    }
    Ok(serde_json::from_slice(&body)?)
}

/// Best-effort `ERROR` frame so the peer aborts cleanly instead of seeing a dropped
/// pipe. Failure to send is ignored — we are already on the error path.
fn send_error<W: Write>(w: &mut W, msg: &str) {
    let _ = write_frame(
        w,
        Tag::Error,
        &ErrorMsg {
            msg: msg.to_string(),
        },
    );
}

// ---------------------------------------------------------------------------
// Store-file enumeration
// ---------------------------------------------------------------------------

/// Names of keystore files A should ship: every regular file in the store dir
/// EXCEPT `keyring.json` (A's enrollments are device-bound and rebuilt on B) and
/// transient `*.hctmp` writes. Sorted for deterministic framing.
fn shippable_files(store: &Path) -> Result<Vec<String>, BootstrapErr> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(store)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "keyring.json" || name.ends_with(".hctmp") {
            continue;
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

// ---------------------------------------------------------------------------
// Authority (A) side
// ---------------------------------------------------------------------------

/// Pick the unlocker A uses to authorize the transfer. A's stdin/stdout are busy
/// with the protocol, so an interactive passphrase prompt is impossible: the
/// supported path is a Secure Enclave enrollment (Touch ID on A). Returns
/// [`BootstrapErr::NoSeAuthority`] if the keyring has no SE enrollment.
fn select_authority_unlocker(keyring: &Keyring) -> Result<SecureEnclaveUnlocker, BootstrapErr> {
    use crate::keyring::EnrollParams;
    let has_se = keyring
        .enrollments
        .iter()
        .any(|e| matches!(e.params, EnrollParams::SecureEnclave { .. }));
    if has_se {
        Ok(SecureEnclaveUnlocker::new(LABEL))
    } else {
        Err(BootstrapErr::NoSeAuthority)
    }
}

/// Authority handshake over an arbitrary transport. `serve_dek` supplies A's DEK
/// (gated behind whatever authorization A requires) and `store` is A's keystore dir.
/// Separated from [`bootstrap_serve`] so tests can drive it over an in-memory pipe.
fn serve<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    dek: &Dek,
    store: &Path,
) -> Result<(), BootstrapErr> {
    // 1. HELLO from B.
    let hello: Hello = read_expect(r, Tag::Hello)?;
    if hello.proto != PROTO {
        send_error(w, "unsupported proto version");
        return Err(BootstrapErr::ProtoMismatch);
    }
    if let Err(e) = check_sec1(&hello.b_se_pub) {
        send_error(w, "bad b_se_pub");
        return Err(e);
    }
    let b_se_pub = hello.b_se_pub;

    // 2. Ephemeral P-256 keypair E; seal the DEK to B under HKDF(ECDH(E, b_se_pub)).
    let eph = EcdhKey::Software(SecretKey::random(&mut rand::rngs::OsRng));
    let eph_pub = match eph.public_sec1() {
        Ok(p) => p,
        Err(e) => {
            send_error(w, "ephemeral key error");
            return Err(e);
        }
    };
    let shared = match eph.ecdh(&b_se_pub) {
        Ok(s) => s,
        Err(e) => {
            send_error(w, "ecdh failed");
            return Err(e);
        }
    };
    let wrap_key = match derive_wrap_key(&shared) {
        Ok(k) => k,
        Err(e) => {
            send_error(w, "hkdf failed");
            return Err(e);
        }
    };
    let aad = bind_aad(&b_se_pub, &eph_pub);
    let enc_dek = match envelope::seal(&wrap_key, &aad, dek.expose()) {
        Ok(f) => f,
        Err(e) => {
            send_error(w, "seal failed");
            return Err(e.into());
        }
    };

    // 3. OFFER, then each keystore file verbatim, then DONE.
    let names = match shippable_files(store) {
        Ok(n) => n,
        Err(e) => {
            send_error(w, "store read failed");
            return Err(e);
        }
    };
    write_frame(
        w,
        Tag::Offer,
        &Offer {
            eph_pub,
            enc_dek,
            manifest: names.clone(),
        },
    )?;

    let mut count: u32 = 0;
    for name in &names {
        let body = std::fs::read(store.join(name))?;
        write_frame(
            w,
            Tag::File,
            &FileMsg {
                name: name.clone(),
                body,
            },
        )?;
        count += 1;
    }
    write_frame(w, Tag::Done, &Done { count })?;

    // 4. Await B's ACK. Anything else is a failed transfer.
    let ack: Ack = read_expect(r, Tag::Ack)?;
    if !ack.ok {
        return Err(BootstrapErr::Protocol);
    }
    tracing::info!(files = count, "bootstrap: DEK delivered and store shipped");
    Ok(())
}

/// Run on the AUTHORITY machine (invoked over SSH as `hot_cheese bootstrap-serve`):
/// serve the handshake over this process's own stdin/stdout.
pub fn bootstrap_serve() -> Result<(), BootstrapErr> {
    let config = Config::load()?;
    let store: PathBuf = config.store_path();
    let keyring = Keyring::load(&store.join("keyring.json"))?;

    let unlocker = select_authority_unlocker(&keyring)?;
    // Touch ID on A authorizes the transfer here.
    let dek = unlocker.unlock(
        "authorize hot_cheese bootstrap to a new machine",
        &keyring,
        None,
    )?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();
    let res = serve(&mut r, &mut w, &dek, &store);
    if let Err(ref e) = res {
        tracing::error!(err = ?e, "bootstrap serve failed");
    }
    res
}

// ---------------------------------------------------------------------------
// Client (B) side
// ---------------------------------------------------------------------------

/// Outcome of a successful client handshake: the recovered DEK plus the staged
/// keystore files (name, raw bytes). The caller decides where to persist them.
struct Received {
    dek: Dek,
    files: Vec<(String, Vec<u8>)>,
}

/// Client handshake over an arbitrary transport. `my_key` does the ECDH that
/// recovers the DEK (Secure Enclave in production, software in tests); `b_se_pub`
/// is `my_key`'s public point as sent in `HELLO`. Persists NOTHING — on any failure
/// (including AEAD open) it returns an error and the caller writes nothing.
/// Separated from [`bootstrap_from`] so tests can drive it over an in-memory pipe.
fn client<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    my_key: &EcdhKey,
    b_se_pub: &[u8],
) -> Result<Received, BootstrapErr> {
    // 1. HELLO with B's SE public key.
    write_frame(
        w,
        Tag::Hello,
        &Hello {
            proto: PROTO,
            b_se_pub: b_se_pub.to_vec(),
        },
    )?;

    // 2. OFFER → recover the DEK via ECDH on B's key.
    let offer: Offer = read_expect(r, Tag::Offer)?;
    if let Err(e) = check_sec1(&offer.eph_pub) {
        send_error(w, "bad eph_pub");
        return Err(e);
    }
    let shared = match my_key.ecdh(&offer.eph_pub) {
        Ok(s) => s,
        Err(e) => {
            send_error(w, "ecdh failed");
            return Err(e);
        }
    };
    let wrap_key = derive_wrap_key(&shared)?;
    let aad = bind_aad(b_se_pub, &offer.eph_pub);
    let dek_bytes = match envelope::open(&wrap_key, &aad, &offer.enc_dek) {
        Ok(b) => b,
        Err(_) => {
            // AEAD failure: wrong key, tamper, or relayed offer. Abort, persist nothing.
            send_error(w, "sealed DEK failed to open");
            return Err(BootstrapErr::DekOpenFailed);
        }
    };
    let dek = {
        let arr: [u8; 32] = match dek_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                let mut z = dek_bytes;
                z.zeroize();
                send_error(w, "bad DEK length");
                return Err(BootstrapErr::Protocol);
            }
        };
        let mut z = dek_bytes;
        z.zeroize();
        Dek::from_bytes(arr)
    };

    // 3. Collect FILE frames into memory until DONE.
    let mut files: Vec<(String, Vec<u8>)> = Vec::with_capacity(offer.manifest.len());
    loop {
        let (tag, body) = read_frame(r)?;
        match tag {
            Tag::File => {
                let f: FileMsg = serde_json::from_slice(&body)?;
                files.push((f.name, f.body));
            }
            Tag::Done => {
                let done: Done = serde_json::from_slice(&body)?;
                if done.count as usize != files.len() {
                    send_error(w, "file count mismatch");
                    return Err(BootstrapErr::Protocol);
                }
                break;
            }
            Tag::Error => {
                let e: ErrorMsg = serde_json::from_slice(&body)?;
                tracing::error!(peer_msg = %e.msg, "bootstrap authority aborted");
                return Err(BootstrapErr::PeerAbort);
            }
            _ => {
                send_error(w, "unexpected frame");
                return Err(BootstrapErr::Protocol);
            }
        }
    }

    Ok(Received { dek, files })
}

/// Write each staged keystore file into `store` (atomically), build a FRESH keyring
/// enrolling the DEK under B's own SE (plus an optional recovery passphrase), and
/// save it to `<store>/keyring.json`. A's `keyring.json` is intentionally NOT copied.
fn persist<F>(store: &Path, received: &Received, enroll_se: F) -> Result<(), BootstrapErr>
where
    F: Fn(&Dek) -> Result<crate::keyring::Enrollment, BootstrapErr>,
{
    // Build the keyring FIRST: enrolling under B's Secure Enclave prompts Touch ID and can
    // fail, so do it before writing any keystore file — a failure then leaves the store
    // untouched rather than orphaning unkeyed ciphertext.
    let mut keyring = Keyring::new();
    keyring.add(enroll_se(&received.dek)?);
    if let Ok(pass) = std::env::var(PASSPHRASE_ENV) {
        if !pass.is_empty() {
            let pu = PassphraseUnlocker::new(pass);
            keyring.add(pu.enroll("bootstrap recovery", &received.dek)?);
        }
    }

    // Write the keystore files and the keyring; on any error remove whatever we wrote this
    // run so we never leave a partial (unkeyed or unrecoverable) store behind.
    std::fs::create_dir_all(store)?;
    if let Err(e) = write_store_and_keyring(store, received, &keyring) {
        for (name, _) in &received.files {
            let _ = std::fs::remove_file(store.join(name));
        }
        let _ = std::fs::remove_file(store.join("keyring.json"));
        return Err(e);
    }
    Ok(())
}

/// Write every received keystore file (atomically) and then the fresh keyring.
fn write_store_and_keyring(
    store: &Path,
    received: &Received,
    keyring: &Keyring,
) -> Result<(), BootstrapErr> {
    for (name, body) in &received.files {
        envelope::atomic_write(&store.join(name), body)?;
    }
    keyring.save(&store.join("keyring.json"))?;
    Ok(())
}

/// Run on the NEW machine: spawn `ssh <target> hot_cheese bootstrap-serve`, recover
/// the DEK (ECIES-sealed to this machine's SE key), receive the store, re-wrap the
/// DEK under this machine's own keyring, and persist everything.
pub fn bootstrap_from(target: &str) -> Result<(), BootstrapErr> {
    use std::process::{Command, Stdio};

    let config = Config::load()?;
    let store: PathBuf = config.store_path();

    // B's Secure Enclave key (created idempotently); its public point is the HELLO id.
    secure_enclave::ensure_se_key(LABEL)?;
    let b_se_pub = secure_enclave::se_public_key(LABEL)?;
    let my_key = EcdhKey::SecureEnclave(LABEL.to_string());

    let mut child = Command::new("ssh")
        .arg(target)
        .arg("hot_cheese")
        .arg("bootstrap-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| BootstrapErr::Ssh)?;

    // Keep both pipe halves alive for the whole ritual: we must send ACK back to A
    // over `w` only AFTER B has safely persisted the DEK.
    let mut w = child.stdin.take().ok_or(BootstrapErr::Ssh)?;
    let mut rd = child.stdout.take().ok_or(BootstrapErr::Ssh)?;

    let received = match client(&mut rd, &mut w, &my_key, &b_se_pub) {
        Ok(r) => r,
        Err(e) => {
            // client() already sent an ERROR frame on protocol/AEAD failures.
            let _ = child.wait();
            return Err(e);
        }
    };

    // Re-wrap under B's own SE and persist BEFORE acknowledging, so we only ACK once
    // the DEK is durably stored on B. The DEK is zeroized when `received` drops.
    match persist(&store, &received, |dek| {
        Ok(SecureEnclaveUnlocker::new(LABEL).enroll("bootstrap (this machine SE)", dek)?)
    }) {
        Ok(()) => {
            write_frame(&mut w, Tag::Ack, &Ack { ok: true })?;
        }
        Err(e) => {
            send_error(&mut w, "failed to persist on new machine");
            let _ = child.wait();
            return Err(e);
        }
    }
    drop(received); // DEK zeroized here
    drop(w); // close B→A so A's serve() reader unblocks after its ACK read

    let status = child.wait().map_err(|_| BootstrapErr::Ssh)?;
    if !status.success() {
        return Err(BootstrapErr::Ssh);
    }
    tracing::info!("bootstrap complete: DEK re-wrapped under this machine's keyring");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A software ECDH key plus its 65-byte SEC1 public point, standing in for a
    /// Secure Enclave endpoint in tests.
    fn sw_key() -> (EcdhKey, Vec<u8>) {
        let sk = SecretKey::random(&mut rand::rngs::OsRng);
        let pubp = sk.public_key().to_sec1_bytes().into_vec();
        (EcdhKey::Software(sk), pubp)
    }

    #[test]
    fn frame_roundtrips_tag_and_payload() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, Tag::Done, &Done { count: 7 }).unwrap();
        let mut cur = Cursor::new(buf);
        let (tag, body) = read_frame(&mut cur).unwrap();
        assert_eq!(tag, Tag::Done);
        let d: Done = serde_json::from_slice(&body).unwrap();
        assert_eq!(d.count, 7);
    }

    #[test]
    fn ecies_core_recovers_dek_across_software_keys() {
        // Simulate A sealing to B and B opening, without any transport.
        let (b_key, b_pub) = sw_key();
        let dek = Dek::random();

        let eph = EcdhKey::Software(SecretKey::random(&mut rand::rngs::OsRng));
        let eph_pub = eph.public_sec1().unwrap();
        let a_shared = eph.ecdh(&b_pub).unwrap();
        let a_wrap = derive_wrap_key(&a_shared).unwrap();
        let aad = bind_aad(&b_pub, &eph_pub);
        let enc = envelope::seal(&a_wrap, &aad, dek.expose()).unwrap();

        let b_shared = b_key.ecdh(&eph_pub).unwrap();
        let b_wrap = derive_wrap_key(&b_shared).unwrap();
        assert_eq!(a_wrap.as_slice(), b_wrap.as_slice(), "ECDH must agree");
        let got = envelope::open(&b_wrap, &aad, &enc).unwrap();
        assert_eq!(got.as_slice(), dek.expose());
    }

    #[test]
    fn wrong_aad_breaks_open() {
        // An OFFER bound to a different B (anti-relay) must not open.
        let (b_key, b_pub) = sw_key();
        let (_other_key, other_pub) = sw_key();
        let dek = Dek::random();

        let eph = EcdhKey::Software(SecretKey::random(&mut rand::rngs::OsRng));
        let eph_pub = eph.public_sec1().unwrap();
        let a_shared = eph.ecdh(&b_pub).unwrap();
        let a_wrap = derive_wrap_key(&a_shared).unwrap();
        let enc = envelope::seal(&a_wrap, &bind_aad(&b_pub, &eph_pub), dek.expose()).unwrap();

        let b_shared = b_key.ecdh(&eph_pub).unwrap();
        let b_wrap = derive_wrap_key(&b_shared).unwrap();
        // B uses the wrong identity in the AAD → AEAD rejects.
        assert!(envelope::open(&b_wrap, &bind_aad(&other_pub, &eph_pub), &enc).is_err());
    }

    /// FULL handshake over two `std::io::pipe()` channels, A and B in separate
    /// threads, using SOFTWARE P-256 keys for both endpoints. Asserts B recovers
    /// A's exact DEK and that every shipped FILE byte transfers intact.
    #[test]
    fn full_handshake_over_pipes_transfers_dek_and_files() {
        // A's keystore dir with two encrypted-looking blobs (opaque bytes; A ships
        // them verbatim and B never decrypts them during bootstrap).
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_bootstrap_test_{}_{}",
            std::process::id(),
            now_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_a = vec![0xABu8; 200];
        let file_b = vec![0xCDu8; 137];
        std::fs::write(dir.join("SOLANA_MAIN"), &file_a).unwrap();
        std::fs::write(dir.join("EVM_HOT"), &file_b).unwrap();
        // A decoy that must NOT be shipped.
        std::fs::write(dir.join("ignored.hctmp"), b"temp").unwrap();
        std::fs::write(dir.join("keyring.json"), b"{}").unwrap();

        let dek = Dek::random();
        let dek_expected = *dek.expose();

        // B's stand-in SE key.
        let (b_key, b_pub) = sw_key();

        // Two pipes: a2b carries A→B, b2a carries B→A.
        let (a2b_r, a2b_w) = std::io::pipe().unwrap();
        let (b2a_r, b2a_w) = std::io::pipe().unwrap();

        let dir_a = dir.clone();
        let authority = std::thread::spawn(move || {
            let mut r = b2a_r;
            let mut w = a2b_w;
            serve(&mut r, &mut w, &dek, &dir_a)
        });

        // Client side (this thread).
        let mut r = a2b_r;
        let mut w = b2a_w;
        let received = client(&mut r, &mut w, &b_key, &b_pub).expect("client handshake");

        // B sends ACK so A's serve() returns Ok.
        write_frame(&mut w, Tag::Ack, &Ack { ok: true }).unwrap();
        drop(w); // close B→A so A's reader can't block

        let serve_res = authority.join().expect("authority thread panicked");
        assert!(serve_res.is_ok(), "serve failed: {:?}", serve_res.err());

        // B recovered A's exact DEK.
        assert_eq!(received.dek.expose(), &dek_expected);

        // Exactly the two real keystore files transferred, byte-for-byte.
        let mut got: std::collections::BTreeMap<String, Vec<u8>> =
            received.files.into_iter().collect();
        assert_eq!(
            got.remove("SOLANA_MAIN").as_deref(),
            Some(file_a.as_slice())
        );
        assert_eq!(got.remove("EVM_HOT").as_deref(), Some(file_b.as_slice()));
        assert!(
            got.is_empty(),
            "unexpected extra files shipped: {:?}",
            got.keys()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
