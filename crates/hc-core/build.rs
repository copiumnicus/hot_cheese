use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const XCRUN: &str = "/usr/bin/xcrun";
const SWIFTC: &str = "/usr/bin/swiftc";

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");

    println!("cargo:rerun-if-changed=swift/se_bridge.swift");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH set by cargo");
    let (swift_arch, min_os) = match arch.as_str() {
        "aarch64" => ("arm64", "11.0"),
        other => (other, "10.15"),
    };
    let target = format!("{swift_arch}-apple-macosx{min_os}");

    let sdk = run_capture(XCRUN, &["--show-sdk-path"]);
    let resource = swift_runtime_resource_path(&target);
    let compat = PathBuf::from(&resource).join("macosx");

    let lib = out_dir.join("libse_bridge.a");
    let module_cache = out_dir.join("swift-module-cache");
    fs::create_dir_all(&module_cache).expect("create the private Swift module cache");
    let status = Command::new(SWIFTC)
        .args([
            "-emit-library",
            "-static",
            "-O",
            "-module-name",
            "se_bridge",
        ])
        .arg("-module-cache-path")
        .arg(&module_cache)
        .args(["-target", &target, "-sdk", &sdk, "-o"])
        .arg(&lib)
        .arg("swift/se_bridge.swift")
        .status()
        .expect("spawn swiftc");
    assert!(
        status.success(),
        "swiftc failed to build swift/se_bridge.swift"
    );

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=se_bridge");
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-search=native={}", compat.display());
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

fn run_capture(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {cmd}: {e}"));
    assert!(out.status.success(), "{cmd} {args:?} failed");
    String::from_utf8(out.stdout)
        .expect("tool output is utf8")
        .trim()
        .to_string()
}

fn swift_runtime_resource_path(target: &str) -> String {
    let info = run_capture(SWIFTC, &["-print-target-info", "-target", target]);
    let parts: Vec<&str> = info.split('"').collect();
    for (i, p) in parts.iter().enumerate() {
        if *p == "runtimeResourcePath" {
            if let Some(path) = parts.get(i + 2) {
                return path.to_string();
            }
        }
    }
    panic!("runtimeResourcePath missing from swiftc -print-target-info");
}
