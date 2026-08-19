//! `init` has to survive a passphrase it refuses. Everything it does before the prompt must leave
//! the install re-initializable, or a first-timer who types a weak passphrase is pushed into
//! `init --force` — the destructive verb that mints a new DEK and demands a typed phrase.
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};

/// Run `init` against a throwaway home with no controlling terminal, so the passphrase prompt
/// (which reads /dev/tty, never stdin) fails instead of blocking on the operator's keyboard.
fn init_without_a_terminal(home: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hot_cheese"));
    command.arg("init").env("HOT_CHEESE_HOME", home);
    // SAFETY: the closure runs between fork and exec in the child and only calls `setsid`, which
    // is async-signal-safe, allocates nothing and touches no state shared with this process.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.output().expect("the hot_cheese binary runs")
}

fn printed(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// A refused passphrase must cost the operator a retry and nothing else: no TLS pair, no config
/// and no `AlreadyInitialized` on the plain re-run.
#[test]
fn a_refused_passphrase_leaves_init_repeatable() {
    let home = std::env::temp_dir().join(format!(
        "hot_cheese_init_retry_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let first = init_without_a_terminal(&home);
    let first_text = printed(&first);
    assert!(
        !first.status.success(),
        "init succeeded without a passphrase: {first_text}"
    );
    assert!(
        first_text.contains("Passphrase(StdIo("),
        "init failed somewhere other than the passphrase prompt: {first_text}"
    );
    for path in [
        home.join("ssl-cert.pem"),
        home.join("ssl-key.pem"),
        home.join("config.toml"),
        home.join("store").join("keyring.json"),
    ] {
        assert!(
            !path.exists(),
            "{} survived a refused passphrase",
            path.display()
        );
    }

    let second = init_without_a_terminal(&home);
    let second_text = printed(&second);
    assert!(
        !second_text.contains("AlreadyInitialized"),
        "a plain re-run was refused after a refused passphrase: {second_text}"
    );
    assert!(
        second_text.contains("Passphrase(StdIo("),
        "the re-run stopped somewhere other than the passphrase prompt: {second_text}"
    );

    std::fs::remove_dir_all(&home).expect("cleanup");
}
