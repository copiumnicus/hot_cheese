use df_share::from_hex_str;
use hot_cheese::{encrypt_key, BackendImpl, Config, MacBackend};
use rand::rngs::OsRng;
use rpassword::read_password;
use std::{env::args, path::Path};
use zeroize::Zeroize;

/// script for adding master password to keychain
/// after this go to keychain and verify that it looks like you want to
/// `cargo run --example add_existing <name> solana|ethereum`
pub fn main() {
    let bytes = include_bytes!("../src/conf/cheese_config.json");
    let conf: Config = serde_json::from_slice(bytes.as_slice()).unwrap();

    let args: Vec<_> = args().into_iter().collect::<Vec<_>>();
    if args.len() < 2 {
        panic!("not enough arguments, need 2")
    }
    let key_type = &args[args.len() - 1];
    let name = &args[args.len() - 2];
    println!("going to encrypt as {} key_type={}", name, key_type);
    let mac = MacBackend::new(&conf.service, &conf.account, &conf.store);
    let path = Path::new(&mac.store_path()).join(&name);
    if path.exists() {
        panic!("key already exists");
    }

    let mut pk = if key_type == "ethereum" {
        println!("provide pk as hex str with 0x or without 0x");
        let mut pks = read_password().expect("fail read pk");
        let pk = from_hex_str(&pks).unwrap();
        pks.zeroize();
        pk
    } else if key_type == "solana" {
        println!("provide pk as base58 encoded string");
        let mut pks = read_password().expect("fail read pk");
        let pk = bs58::decode(&pks).into_vec().unwrap();
        pks.zeroize();
        pk
    } else {
        panic!("expected key_type to be 'solana' or 'ethereum'")
    };

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
