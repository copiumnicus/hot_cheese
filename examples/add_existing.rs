use df_share::from_hex_str;
use hot_cheese::{encrypt_key, BackendImpl, Config, MacBackend};
use rand::rngs::OsRng;
use rpassword::read_password;
use std::{env::args, path::Path};
use zeroize::Zeroize;

/// script for adding master password to keychain
/// after this go to keychain and verify that it looks like you want to
/// `cargo run --example add_existing <name>`
pub fn main() {
    let bytes = include_bytes!("../src/cheese_config.json");
    let conf: Config = serde_json::from_slice(bytes.as_slice()).unwrap();

    let name = args().last().expect("expect name of key");
    println!("going to encrypt as {}", name);
    let mac = MacBackend::new(&conf.service, &conf.account, &conf.store);
    let path = Path::new(&mac.store_path()).join(&name);
    if path.exists() {
        panic!("key already exists");
    }

    println!("provide pk as hex str with 0x or without 0x");
    let mut pks = read_password().expect("fail read pk");
    let mut pk = from_hex_str(&pks).unwrap();
    pks.zeroize();

    // more important so get second
    println!("get master to encrypt");
    if !mac.is_device_owner("to_encrypt_key") {
        panic!("not device owner");
    }
    let mut master = mac.get_encryption_key().expect("fail get master");

    let mut rng = OsRng::default();
    encrypt_key(mac.store_path(), &mut rng, &pk, &master, &name).expect("fail encrypt");
    master.zeroize();
    pk.zeroize()
}
