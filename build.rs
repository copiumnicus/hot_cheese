fn main() {
    // Detect the build profile
    // let profile = std::env::var("PROFILE").expect("no PROFILE");
    println!("cargo:rustc-link-search=native=./target/debug");
    println!("cargo:rustc-link-lib=dylib=main");
    // pass rpath config to linker
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../Frameworks");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
