use hot_cheese::{run_server, MacBackend};

fn main() {
    run_server(Box::new(MacBackend::new(
        "com.example.myapp",
        "myusername",
        "~/HOT_CHEESE_TEST",
    )))
    .unwrap()
}
