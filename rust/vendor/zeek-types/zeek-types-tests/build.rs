use std::{env, fs, os, path::PathBuf};

use cargo_emit::{rerun_if_changed, rustc_link_arg};

fn main() {
    rerun_if_changed!("build.rs");

    allow_underlinking();
    setup_plugin();
}

fn allow_underlinking() {
    // Allow underlinking since symbols from Zeek are only resolved when a plugin is loaded into Zeek.
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target.as_str() {
        "macos" => {
            rustc_link_arg!("-Wl,-undefined,dynamic_lookup");
        }
        "linux" => {
            rustc_link_arg!("-Wl,--allow-shlib-undefined");
        }
        _ => panic!("unsupported target {target}"),
    }
}

fn setup_plugin() {
    let out_dir: PathBuf = env::var("OUT_DIR").unwrap().into();

    let dist = scratch::path("dist");

    // Write the marker file.
    let marker = dist.join("__zeek_plugin__");
    let _ = fs::remove_file(&marker);
    fs::write(&marker, format!("{}\n", env!("CARGO_PKG_NAME"))).unwrap();

    // Put a link to the library in the expected spot with expected name.
    let lib_dir = dist.join("lib");
    let _ = fs::remove_dir_all(&lib_dir);
    fs::create_dir(&lib_dir).unwrap();
    let mut dir = out_dir.clone();
    while !dir.ends_with("build") {
        dir.pop();
    }
    dir.pop();
    let lib_name = env::var("CARGO_PKG_NAME").unwrap().replace("-", "_");
    let dylib = if cfg!(target_os = "macos") {
        format!("lib{}.dylib", lib_name)
    } else {
        format!("lib{}.so", lib_name)
    };
    let dylib = dir.join(dylib);
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let os = match os.as_str() {
        "macos" => "darwin",
        _ => {
            panic!("unsupported target OS '{os}'");
        }
    };
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let arch = match arch.as_str() {
        "aarch64" => "arm64",
        _ => {
            panic!("unsupported target architecture '{arch}'");
        }
    };
    let new_name = lib_dir.join(format!("lib{lib_name}.{os}-{arch}.so"));

    os::unix::fs::symlink(dylib, &new_name).unwrap();
}
