//! Runtime configuration + on-disk locations.
//!
//! Replaces the old compile-time `include_bytes!("conf/cheese_config.json")` so the
//! store path, port, certs, and backup remotes can change without a rebuild.
use crate::resolve_path;
use alloy_primitives::{Address, U256};
use err_mac::create_err_with_impls;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Legacy Keychain service name (used only by `migrate` to read the old master).
    pub service: String,
    /// Legacy Keychain account name (migration only).
    pub account: String,
    /// Directory holding the encrypted keystores + `keyring.json`.
    pub store: String,
    #[serde(default)]
    pub port: Option<u16>,
    /// Uncompressed SEC1 hex (65 bytes) of the Secure Enclave grant key `serve` must find.
    #[serde(default)]
    pub grant_public_key: Option<String>,
    /// Seconds `bundle watch` waits between polls.
    #[serde(default)]
    pub bundle_watch_secs: Option<u64>,
    /// Limits on what the MCP proposal server may leave in the review queue.
    #[serde(default)]
    pub mcp: Option<Mcp>,
    #[serde(default)]
    pub backup_remotes: Vec<BackupRemote>,
    /// Out-of-process signing adapters this machine trusts.
    #[serde(default)]
    pub adapters: Vec<AdapterPin>,
    /// Tailnet machines this install syncs `bundles/` with.
    #[serde(default)]
    pub bundle_peers: Vec<BundlePeer>,
    /// Contracts whose base units an approval summary may also render scaled and named.
    #[serde(default)]
    pub token: Vec<TokenAnnotation>,
    /// Operator-chosen names an approval summary may show beside an address.
    #[serde(default)]
    pub label: Vec<LabelAnnotation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupRemote {
    /// SSH target, e.g. "user@1.2.3.4".
    pub host: String,
    /// Remote folder under the home dir, e.g. "hot_cheese_store".
    pub folder: String,
}

/// Where a peer keeps its bundles when `config.toml` does not say otherwise.
const DEFAULT_PEER_BUNDLES_DIR: &str = ".config/hot_cheese/bundles";

/// Unsigned bundles an agent may leave waiting before the proposal server refuses to file
/// another. The queue is read by a human, so it is bounded by what a human will read.
const DEFAULT_MCP_MAX_PENDING: usize = 16;

/// What an agent proposing over MCP is allowed to accumulate.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mcp {
    /// Bundle directories that must already exist before a proposal is refused.
    #[serde(default)]
    pub max_pending: Option<usize>,
}

/// One tailnet machine this install exchanges Safe bundles with over rsync-on-ssh.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundlePeer {
    /// SSH target: the peer's MagicDNS name, optionally `user@`-prefixed.
    pub host: String,
    /// The peer's bundles dir; a relative path resolves against its home dir.
    #[serde(default)]
    pub dir: Option<String>,
}

impl BundlePeer {
    pub fn dir(&self) -> &str {
        self.dir.as_deref().unwrap_or(DEFAULT_PEER_BUNDLES_DIR)
    }
    /// The ssh target without any `user@` prefix, which is what the tailnet knows it as.
    pub fn name(&self) -> &str {
        match self.host.split_once('@') {
            Some((_, host)) => host,
            None => &self.host,
        }
    }
}

/// One trusted adapter: which manifest, and the exact bytes that manifest must be.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdapterPin {
    /// Adapter id: names its manifest, its socket, and the provenance on the approval prompt.
    pub id: String,
    /// Manifest path; a relative one resolves under the home dir.
    pub manifest: String,
    /// SHA-256 hex the manifest bytes must hash to before they are parsed.
    pub sha256: String,
}

impl AdapterPin {
    pub fn manifest_path(&self) -> PathBuf {
        let path = resolve_path(&self.manifest);
        if path.is_absolute() {
            return path;
        }
        home_dir().join(path)
    }
}

/// The token interface a contract implements, which is what decides whether its integer
/// argument is a quantity at all: scaling a `tokenId` by a fungible token's decimals would
/// render token #42 as `0.000042`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenStandard {
    Erc20,
    Erc721,
    Erc1155,
}

/// One contract an approval summary may name and scale amounts for.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenAnnotation {
    /// The contract the Safe calls; `0x0` annotates the chain's native asset.
    pub address: Address,
    /// Chain the contract is deployed on.
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    /// Ticker shown beside the scaled amount.
    pub symbol: String,
    /// Base-unit exponent; must be 0 unless the standard is fungible.
    pub decimals: u8,
    pub standard: TokenStandard,
}

/// One address an approval summary may name.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelAnnotation {
    /// The address being named.
    pub address: Address,
    /// Chain the name applies on.
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    /// The name, appended to the address and never substituted for it.
    pub name: String,
}

/// Why operator-authored annotation text may not reach an approval sheet.
#[derive(Debug)]
pub enum TextRefusal {
    Empty,
    TooLong,
    NotPrintableAscii,
    Parenthesis,
    AddressPrefix,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ConfigErr,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Toml(toml::de::Error),
    TomlSer(toml::ser::Error),
    Envelope(crate::crypto::envelope::EnvErr)
    ;
    AnnotationTextRefused {
        address: Address,
        text: String,
        refusal: TextRefusal,
    },
    DecimalsOnNonFungible {
        address: Address,
        standard: TokenStandard,
        decimals: u8,
    },
    DuplicateToken {
        address: Address,
        chain_id: U256,
    },
    DuplicateLabel {
        address: Address,
        chain_id: U256,
    }
);

/// Characters of annotation text an approval sheet has room for.
const MAX_ANNOTATION_CHARS: usize = 32;

/// Judge one piece of operator-authored text that an approval summary will print. It is
/// operator-authored but frequently pasted from whoever asked to be paid, so it is untrusted
/// text in a security-critical string: a newline could forge a `⚠` line or push the real
/// content off the three lines a Touch ID sheet shows, a parenthesis could close the one the
/// renderer opened and open a second, and a `0x` prefix could pass for an address.
fn annotation_text(text: &str) -> Result<(), TextRefusal> {
    if text.is_empty() {
        return Err(TextRefusal::Empty);
    }
    if text.chars().count() > MAX_ANNOTATION_CHARS {
        return Err(TextRefusal::TooLong);
    }
    if !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err(TextRefusal::NotPrintableAscii);
    }
    if text.contains('(') || text.contains(')') {
        return Err(TextRefusal::Parenthesis);
    }
    if text.starts_with("0x") || text.starts_with("0X") {
        return Err(TextRefusal::AddressPrefix);
    }
    Ok(())
}

/// `$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`.
pub fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOT_CHEESE_HOME") {
        return PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config").join("hot_cheese");
    }
    PathBuf::from(".hot_cheese")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.toml")
}

/// `<home>/adapters`: adapter manifests and their sockets. Deliberately outside the store, so
/// adapter trust is per-machine and never travels with a backup or an SSH bootstrap.
pub fn adapters_dir() -> PathBuf {
    home_dir().join("adapters")
}

/// `<home>/adapters/<id>.sock`, the one socket that carries adapter `id`'s provenance.
pub fn adapter_socket(id: &str) -> PathBuf {
    adapters_dir().join(format!("{id}.sock"))
}

/// `<home>/bundles`: `safes.toml` and one directory per SafeTx being collected. Deliberately
/// outside the store, which backup replicates per vault: two machines hold deliberately
/// different signer keys, and a bundle — public fields plus signatures over a public digest —
/// must never ride the path that carries key material.
pub fn bundles_dir() -> PathBuf {
    home_dir().join("bundles")
}

/// `<home>/bundle-quarantine`: where a file a peer pushed goes when it fails verification.
/// Outside `bundles/` on purpose, so nothing quarantined is ever synced back out.
pub fn bundle_quarantine_dir() -> PathBuf {
    home_dir().join("bundle-quarantine")
}

/// (cert.pem, key.pem) under the home dir.
pub fn cert_paths() -> (PathBuf, PathBuf) {
    let h = home_dir();
    (h.join("ssl-cert.pem"), h.join("ssl-key.pem"))
}

/// Max tracing level from `RUST_LOG` (case-insensitive level word), defaulting to INFO.
pub fn env_log_level() -> tracing::Level {
    match std::env::var("RUST_LOG").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("trace") => tracing::Level::TRACE,
        Some(v) if v.eq_ignore_ascii_case("debug") => tracing::Level::DEBUG,
        Some(v) if v.eq_ignore_ascii_case("warn") => tracing::Level::WARN,
        Some(v) if v.eq_ignore_ascii_case("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
}

impl Config {
    pub fn store_path(&self) -> PathBuf {
        resolve_path(&self.store)
    }
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(5555)
    }
    pub fn bundle_watch_secs(&self) -> u64 {
        self.bundle_watch_secs.unwrap_or(15)
    }
    pub fn mcp_max_pending(&self) -> usize {
        match &self.mcp {
            Some(mcp) => mcp.max_pending.unwrap_or(DEFAULT_MCP_MAX_PENDING),
            None => DEFAULT_MCP_MAX_PENDING,
        }
    }
    /// Refuse an annotation table that could mislead the human reading an approval summary:
    /// text that could forge structure in it, a `decimals` a non-fungible standard has no
    /// meaning for, and a second entry for a `(address, chain_id)` the first already answers —
    /// an entry that can never fire is one the operator wrongly believes in.
    fn validate(&self) -> Result<(), ConfigErr> {
        for (i, token) in self.token.iter().enumerate() {
            if let Err(refusal) = annotation_text(&token.symbol) {
                return Err(ConfigErr::AnnotationTextRefused {
                    address: token.address,
                    text: token.symbol.clone(),
                    refusal,
                });
            }
            let fungible = match token.standard {
                TokenStandard::Erc20 => true,
                TokenStandard::Erc721 | TokenStandard::Erc1155 => false,
            };
            if !fungible && token.decimals != 0 {
                return Err(ConfigErr::DecimalsOnNonFungible {
                    address: token.address,
                    standard: token.standard,
                    decimals: token.decimals,
                });
            }
            for other in &self.token[i + 1..] {
                if other.address == token.address && other.chain_id == token.chain_id {
                    return Err(ConfigErr::DuplicateToken {
                        address: token.address,
                        chain_id: token.chain_id,
                    });
                }
            }
        }
        for (i, label) in self.label.iter().enumerate() {
            if let Err(refusal) = annotation_text(&label.name) {
                return Err(ConfigErr::AnnotationTextRefused {
                    address: label.address,
                    text: label.name.clone(),
                    refusal,
                });
            }
            for other in &self.label[i + 1..] {
                if other.address == label.address && other.chain_id == label.chain_id {
                    return Err(ConfigErr::DuplicateLabel {
                        address: label.address,
                        chain_id: label.chain_id,
                    });
                }
            }
        }
        Ok(())
    }
    pub fn load() -> Result<Self, ConfigErr> {
        let path = config_path();
        if !path.exists() {
            let legacy = home_dir().join("config.json");
            if legacy.exists() {
                let cfg: Config = serde_json::from_slice(&std::fs::read(&legacy)?)?;
                cfg.validate()?;
                cfg.save()?;
                std::fs::remove_file(&legacy)?;
                return Ok(cfg);
            }
        }
        let cfg: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
        cfg.validate()?;
        Ok(cfg)
    }
    /// A config for tests that build a `HotApi` directly: the store, plus the P-256 base
    /// point standing in for a pinned grant key so the sign path reaches its approver (no
    /// test owns an enclave, so none of them reaches the mint that key would answer).
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(store: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            service: String::new(),
            account: String::new(),
            store: store.to_string(),
            port: None,
            grant_public_key: Some(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                    .to_string(),
            ),
            bundle_watch_secs: None,
            mcp: None,
            backup_remotes: Vec::new(),
            adapters: Vec::new(),
            bundle_peers: Vec::new(),
            token: Vec::new(),
            label: Vec::new(),
        })
    }
    pub fn save(&self) -> Result<(), ConfigErr> {
        let text = toml::to_string_pretty(self)?;
        let p = config_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::crypto::envelope::atomic_write(&p, text.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n";

    fn loaded(tables: &str) -> Result<Config, ConfigErr> {
        let cfg: Config = toml::from_str(&format!("{HEAD}{tables}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn label(name: &str) -> Result<Config, ConfigErr> {
        loaded(&format!(
            "[[label]]\naddress = \"0x2222222222222222222222222222222222222222\"\n\
             chain_id = 1\nname = \"{name}\"\n"
        ))
    }

    /// A label is pasted text that a summary prints inside `address (name)`, so the shapes that
    /// could forge structure there — a newline that fakes a ⚠ line or pushes the real content off
    /// a three-line sheet, a paren that closes the renderer's and opens its own, an address-like
    /// prefix, and anything too long for the sheet — must all die before an approval ever runs.
    #[test]
    fn label_text_that_could_forge_an_approval_line_dies_at_load() {
        assert!(label("Vendor payouts").is_ok());
        for forged in [
            r"Vendor\npayouts",
            "Vendor (payouts",
            "Vendor payouts)",
            "0xdeadbeef",
            "",
            &"a".repeat(33),
        ] {
            assert!(
                matches!(
                    label(forged),
                    Err(ConfigErr::AnnotationTextRefused { .. })
                ),
                "{forged:?} must not reach an approval sheet"
            );
        }
        assert!(label(&"a".repeat(32)).is_ok());
    }

    /// A second entry for a `(address, chain_id)` the first already answers can never fire, and a
    /// `decimals` on a standard whose integer is an id and not a quantity would render token #42
    /// as `0.000042`. Both are operator beliefs the renderer would not honour, so neither loads.
    #[test]
    fn annotation_tables_refuse_entries_that_could_never_be_honoured() {
        let two = concat!(
            "[[label]]\naddress = \"0x2222222222222222222222222222222222222222\"\n",
            "chain_id = 1\nname = \"Vendor payouts\"\n\n",
            "[[label]]\naddress = \"0x2222222222222222222222222222222222222222\"\n",
            "chain_id = 1\nname = \"Attacker\"\n",
        );
        assert!(matches!(
            loaded(two),
            Err(ConfigErr::DuplicateLabel { .. })
        ));

        let other_chain = two.replace("chain_id = 1\nname = \"Attacker\"", "chain_id = 10\nname = \"Attacker\"");
        assert!(loaded(&other_chain).is_ok());

        let token = |standard: &str, decimals: u8| {
            loaded(&format!(
                "[[token]]\naddress = \"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\"\n\
                 chain_id = 1\nsymbol = \"USDC\"\ndecimals = {decimals}\nstandard = \"{standard}\"\n"
            ))
        };
        assert!(token("erc20", 6).is_ok());
        assert!(token("erc721", 0).is_ok());
        assert!(matches!(
            token("erc721", 6),
            Err(ConfigErr::DecimalsOnNonFungible { .. })
        ));
        assert!(matches!(
            token("erc1155", 6),
            Err(ConfigErr::DecimalsOnNonFungible { .. })
        ));
    }
}
