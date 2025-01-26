use hot_cheese::{run_server, Config, MacBackend};

fn main() {
    // so everybody can customize the storage and name of service and account
    // and embed it in the binary
    let bytes = include_bytes!("./cheese_config.json");
    let conf: Config = serde_json::from_slice(bytes.as_slice()).unwrap();
    run_server(Box::new(MacBackend::new(
        &conf.service,
        &conf.account,
        &conf.store,
    )))
    .unwrap()
}
