//! The weakest of this crate's three fences, stated honestly: a string search, not a type.
//!
//! What actually keeps the proposal server away from a key is structural — `hc-daemon` is not a
//! dependency, so the signing API cannot be named, and `hc-core/tests/boundary.rs` asserts that
//! against the real build graph. Both survive any edit. This one is a test, and a future edit
//! can simply delete it. It is here because a name appearing in this crate's source is the
//! earliest visible sign that someone is re-opening the path the other two fences close.
use std::path::{Path, PathBuf};

/// Names on the key path. Source here that mentions one is either reaching for the enclave or
/// re-implementing something that must stay behind a biometric in `hc-core` / `hc-sign`.
const FORBIDDEN: [&str; 13] = [
    "MacBackend",
    "BackendImpl",
    "unlock_dek",
    "Unlocker",
    "LaContext",
    "secure_enclave",
    "decrypt_file",
    "encrypt_file",
    "sign_with_grant",
    "grant::mint",
    "grant::verify",
    "sign::finish",
    "export_permit",
];

#[test]
fn no_source_file_names_the_key_path() {
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    let mut read = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a source directory") {
            let path: PathBuf = entry.expect("read a directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read a source file");
            for name in FORBIDDEN {
                assert!(
                    !text.contains(name),
                    "{} names {name}, which belongs to the key path",
                    path.display()
                );
            }
            read += 1;
        }
    }
    assert!(
        read >= 4,
        "the walk read {read} files; it is not reading the crate"
    );
}
