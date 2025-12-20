#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use cargo_emit::rerun_if_changed;
use std::process::Command;

fn main() -> Result<(), String> {
    // Force prefix to be compatible with corrosion-style build.
    use cxx_build::CFG;
    CFG.include_prefix = "zeek_types_cxx";

    let mut bridge = cxx_build::bridge("src/lib.rs");
    // Skip building bridge if we are building with corrosion in which case the bridge will be
    // built with CMake.
    if !cfg!(feature = "corrosion") {
        bridge
            .file("src/interop.cc")
            .include("src/")
            .includes(&zeek_include_dirs()?)
            .flag_if_supported("-Wno-unused-parameter")
            .std("c++20")
            .compile("zeek-types");

        rerun_if_changed!("build.rs");
        rerun_if_changed!("src/lib.rs");
        rerun_if_changed!("src/interop.h");
        rerun_if_changed!("src/interop.cc");
    }

    Ok(())
}

fn zeek_include_dirs() -> Result<Vec<String>, String> {
    let output = Command::new("zeek-config")
        .arg("--include_dir")
        .output()
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    Ok(stdout.split(':').map(str::to_owned).collect())
}
