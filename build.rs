use std::env;
use std::fs;
use std::process::Command;

fn main() {
    // Detect the build profile
    let profile = env::var("PROFILE").expect("PROFILE environment variable not set");
    // Determine the target directory based on the profile
    let target_dir = format!("target/{}", profile);

    // Ensure the target directory exists
    fs::create_dir_all(&target_dir).expect("Failed to create target directory");

    // Compile the Swift library into the appropriate directory
    let dylib_path = format!("{}/libtouchid.dylib", target_dir);
    let output = Command::new("swiftc")
        .args(&["-emit-library", "-o", &dylib_path, "swift/main.swift"])
        .status()
        .expect("Failed to compile Swift library");

    if !output.success() {
        panic!("Failed to compile Swift library");
    }

    // Use install_name_tool to set @rpath in the dylib
    let output = Command::new("install_name_tool")
        .args(&["-id", "@rpath/libtouchid.dylib", &dylib_path])
        .status()
        .expect("Failed to set rpath with install_name_tool");

    if !output.success() {
        panic!("Failed to set @rpath on the Swift library");
    }

    // Link the Rust binary with the dylib
    println!("cargo:rustc-link-search=native={}", target_dir);
    println!("cargo:rustc-link-lib=dylib=touchid");

    // Set the runtime search path for the binary
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../Frameworks");
}
