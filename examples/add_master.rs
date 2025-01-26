use hot_cheese::Config;
use rpassword::read_password;
use std::process::Command;
use zeroize::Zeroize;

/// Verifies that the password contains only shell-safe characters (lowercase, uppercase, numbers)
fn verify_password(password: &str) -> bool {
    password.chars().all(|c| c.is_ascii_alphanumeric())
}
/// script for adding master password to keychain
/// after this go to keychain and verify that it looks like you want to
/// cargo run --example add_master
pub fn main() {
    let bytes = include_bytes!("../src/cheese_config.json");
    let conf: Config = serde_json::from_slice(bytes.as_slice()).unwrap();
    println!("reading password");
    let mut master_password = read_password().expect("Failed to read password");
    if !verify_password(&master_password) {
        panic!("master needs to be alphanumeric to be shell safe")
    }
    println!("repeat password");
    let mut rep_master_password = read_password().expect("Failed to read password");
    if master_password != rep_master_password {
        rep_master_password.zeroize();
        master_password.zeroize();
        panic!("passwords don't match")
    }
    let status = Command::new("security")
        .arg("add-generic-password")
        .arg("-a")
        .arg(&conf.account)
        .arg("-s")
        .arg(&conf.service)
        .arg("-w")
        .arg(&master_password)
        .status();
    rep_master_password.zeroize();
    master_password.zeroize();

    if !status.unwrap().success() {
        panic!("Failed to add master password to keychain")
    }
}
