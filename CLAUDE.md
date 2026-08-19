# Engineering Rules

hot_cheese is a native macOS daemon that holds signing keys (EVM/Solana) encrypted at rest behind an envelope: a random DEK encrypts each keystore, and the DEK is wrapped under a Secure-Enclave KEK (Touch ID) and a recovery-passphrase KEK. Keys are released or used only after a per-request, biometric-gated unlock. These rules are binding.

## Orchestration

- Claude Code works on this repo as an ORCHESTRATOR ONLY. Delegate all code-writing and all code-auditing to subagents.
- Why: subagents have fresh context and spend more tokens, which produces better and complete results. Working directly, the main loop stops early ("that's all I can do this session") — nobody wants that. We want the work done and correct.
- Tell every child agent that it is a child, so it does not spawn its own children.

## Structure

- DON'T mirror a config struct into a second runtime struct. Use the config struct directly in the code.
- Run the daemon from a single TOML config file, not CLI flags. Configure through TOML. Env vars are allowed ONLY for secrets and the explicit Secure-Enclave / demo toggles.
- Private key material exists in plaintext ONLY transiently, after a Secure-Enclave-gated unlock, and is zeroized immediately. Never persist, log, or Debug-print a key. Never add a path that reads a key outside the DEK envelope.
- Represent a fixed set of choices as an ENUM, not strings. Use the type system (chain, secret kind, unlock method).
- Use serde derives. Don't hand-write Serialize/Deserialize unless it is a genuinely new wire format.
- When moving code, DON'T reexport shims. Fix the whole path. Reexport shims are lazy spaghetti of deps.
- When replacing code, fix the ENTIRE path. No shims.
- NEVER run rayon inside the tokio async runtime. It deadlocks the thread.
- NEVER format an error to a string. Every failure is a variant in a typed error enum (this repo's workspace-owned `err_mac::create_err_with_impls!` provides the shared declaration macro).
- NEVER return Option. Return Result with a typed error. Option is allowed only when None is a genuine and correct value.
- Serialize U256 as decimal. Accept decimal OR hex on deserialize.
- For Ethereum types use the real Rust counterparts (alloy: Address, U256, Bytes, TxKind), never strings or Vec<u8>.

## Errors

- Do NOT remap errors case-by-case. Nest the inner error as a variant (`Outer::Inner { source }` with `#[from]`) so `?` unwraps library errors into your enum with no `map_err`.

## Behaviour

- DON'T make things up. If you didn't read it, it isn't real. Evidence for claims is required.
- DON'T hardcode. Use the config.
- HashMaps and HashSets are NOT ordered. Know your data structures.
- ALWAYS build and run in RELEASE. Debug is 10-100x slower here (Argon2, scrypt, ECDH, the SE self-test, serve) and it matters.
- Silencing clippy is BANNED. `#[allow(clippy::...)]` is you ignoring clippy telling you the code is bad. Fix the code.
- Whenever you upgrade a part of the system, find EVERY now-dead path and DELETE it. The one deliberate exception is the legacy Web3 keystore reader, kept solely for `migrate`.

## Running hot_cheese

- hot_cheese runs NATIVELY on macOS. It CANNOT run in Docker: it needs the Secure Enclave, Touch ID, and the login Keychain, which are host-only.
- The daemon is `hot_cheese serve`. Management is via subcommands (init, enroll, add, generate, address, list, backup, migrate, bootstrap-from). hot_cheese is a pure CLI: there is no GUI.
- NEVER call `/read/<name>`, `/evm_address/<name>`, or `/solana_address/<name>` casually or as a health check. EACH decrypts a private key and prompts the owner for Touch ID approval on EVERY call. Spamming them spams a human. The health endpoint is `/health`.
- The Secure Enclave path requires a code-signed binary (Team-ID entitlements). The software-enclave demo (`HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1` with a throwaway `HOT_CHEESE_HOME`) previews the exact flow unsigned. It is a preview only, never for real keys.
- There is no GUI, menu-bar app, or web frontend: hot_cheese ships only as the `hot_cheese` CLI binary. Build and run it with `cargo build --release` / `cargo run --release -- <subcommand>`.
- Never strand a stray daemon. Don't background `serve` with `&`, `nohup`, or `setsid`. Run it in the foreground.

## Tests

- Tests that assert if-statements work are useless. `if` works in Rust. Read the body instead of testing "returns Err when the token is not in the map".
- Same for arithmetic. A test that a `>=` works wastes 30 lines.
- Don't test that serde serializes or deserializes. It does. Only test a serde handler you actually wrote.
- The only good test enforces NEW non-trivial logic we wrote, or a crucial non-trivial invariant. Language primitives work, even wrapped in a function. Don't test them.

## Comments

- You are BANNED from comments in main code. Express a property in code, not an essay over a line. Prose doesn't change behaviour, it only confuses the next reader.
- Allowed: struct field docs, ONE short sentence per field. Test purpose, ONE short sentence.
- NOT allowed: comments in `.sh`, in TOML, in `Cargo.toml`. Logs and prints dressed up as explanations. Error messages as prose: a failure is a typed variant holding the offending values in fields, `#[error(...)]` a terse label, never a `format!` essay.

## Functions

- Create a function ONLY if it is reused in multiple places, OR to prove non-trivial properties (more than an if or arithmetic) with a test.
- No no-logic functions. Taking four args and returning their sum is boilerplate, not a function.
- `#[allow(clippy::too_many_arguments)]` is banned. Too many args is a hint your code is bad.
- If the args are the fields of the value you return, you are assembling a struct that already exists. Take it in. A builder is not the answer.

## Variables

- Don't create variables only to pass them to a function. If they are grouped in a struct, or the function needs most of a struct's fields, pass the struct or put the method on the struct.
- Creating a variable to guard-unwrap a Result before continuing is fine.

## Std

- Use hashbrown's HashMap and HashSet, not std.
- Use parkinglot's Mutex and RwLock, not std. std locks POISON on panic: one panic under the guard and every later `.lock()` panics forever, permanently 500ing the service until restart. parkinglot does not poison, which is why it has no `.unwrap()`. Everywhere, including appstate, test fakes, and examples. No exceptions.

## Git

- Don't push, commit, stage, or create branches or worktrees. Write on the current branch. Don't ask to commit.
