use std::process::Command;

fn main() {
    // Detect the build profile
    let profile = std::env::var("PROFILE").expect("PROFILE environment variable not set");
    // Determine the target directory based on the profile
    let target_dir = format!("target/{}", profile);

    // for debug can check symbols: nm -gU ./libtouchid.dylib
    // Compile the Swift library during the Rust build process if needed
    let output = Command::new("swiftc")
        .args(&[
            "-emit-library",
            "-o",
            format!("{}/libtouchid.dylib", target_dir).as_str(),
            "swift/main.swift",
        ])
        .status()
        .expect("Failed to compile Swift library");

    if !output.success() {
        panic!("Failed to compile Swift library");
    }

    // Specify the path to the `.dylib`
    println!("cargo:rustc-link-search=native={}", target_dir);
    println!("cargo:rustc-link-lib=dylib=touchid");
}
