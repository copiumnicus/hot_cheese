use hot_cheese::{resolve_path, Config};
use serde_json;
use std::{env, path::Path, process::Command};

// Usage: cargo run --example simple_backup <remote_host>
fn main() {
    // 1. Read cheese_config.json
    let bytes = include_bytes!("../src/conf/cheese_config.json");
    let conf: Config =
        serde_json::from_slice(bytes).expect("Failed to deserialize cheese_config.json");

    // 2. Grab the remote host from the first command-line argument
    let remote_host = env::args()
        .nth(1)
        .expect("Usage: cargo run --example simple_backup <remote_host>");

    // 3. Resolve and verify the store path from the config
    let resolved_store_path = resolve_path(&conf.store);
    let store_path = Path::new(&resolved_store_path);

    if !store_path.exists() || !store_path.is_dir() {
        panic!(
            "The configured store path '{}' does not exist or is not a directory",
            store_path.display()
        );
    }

    // 4. Extract just the folder name (e.g., "hot_cheese_keys" from "/Users/.../hot_cheese_keys")
    let folder_name = store_path
        .file_name()
        .unwrap_or_else(|| {
            panic!(
                "Could not extract folder name from '{}'",
                store_path.display()
            )
        })
        .to_str()
        .expect("Failed to convert folder name to UTF-8 string");

    // 5. Define the paths to ssl-cert, ssl-key, cheese_config.json
    let conf_path = Path::new("src/conf");

    // 6. Construct and run the rsync command
    //    -a  : archive mode (preserves attributes)
    //    -v  : verbose
    //    -z  : compress data
    //    The trailing slash ensures we sync the *contents* of the local folder into the remote folder.
    let status = Command::new("rsync")
        .arg("-avz")
        // The local store path (with a trailing slash to copy contents)
        .arg(format!("{}/", store_path.display()))
        // Additional files to copy
        .arg(conf_path)
        // The remote destination, preserving the folder name in the user's home directory
        .arg(format!("{}:~/{}/", remote_host, folder_name))
        .status()
        .expect("Failed to spawn rsync process");

    if !status.success() {
        panic!("rsync failed with status: {:?}", status);
    }

    // 7. Print success message
    println!(
        "Backup completed successfully to {}:~/{}/",
        remote_host, folder_name
    );
}
