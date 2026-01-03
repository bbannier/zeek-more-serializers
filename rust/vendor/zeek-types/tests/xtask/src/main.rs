use std::{env, fs, os, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the location of a plugin previously packaged with 'dist'.
    DistDir,
    /// Prepare a crate to be loadabed as a Zeek plugin.
    Dist {
        /// Name of the crate to package.
        plugin: String,
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::DistDir => dist_dir(),
        Command::Dist { plugin, .. } => dist(plugin),
    }
}

fn dist_dir() -> Result<()> {
    let dist = scratch::path("dist");
    let dist = dist
        .to_str()
        .expect(&format!("path '{dist:?}' is not valid UTF-8"));
    println!("{dist}");

    Ok(())
}

fn dist(package: String) -> Result<()> {
    // Build the package.
    std::process::Command::new("cargo")
        .args(&["build", "--package", &package])
        .status()?;

    let out_dir: PathBuf = env!("OUT_DIR").into();

    let dist = scratch::path("dist");

    // Write the marker file.
    let marker = dist.join("__zeek_plugin__");
    let _ = fs::remove_file(&marker);
    fs::write(&marker, format!("{package}\n")).unwrap();

    // Put a link to the library in the expected spot with expected name.
    let lib_dir = dist.join("lib");
    let _ = fs::remove_dir_all(&lib_dir);
    fs::create_dir(&lib_dir).unwrap();
    let mut dir = out_dir.clone();
    while !dir.ends_with("build") {
        dir.pop();
    }
    dir.pop();
    let lib_name = package.replace("-", "_");
    let dylib = if cfg!(target_os = "macos") {
        format!("lib{}.dylib", lib_name)
    } else {
        format!("lib{}.so", lib_name)
    };
    let dylib = dir.join(dylib);
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let os = match os.as_str() {
        "macos" => "darwin",
        "linux" => "linux",
        _ => {
            panic!("unsupported target OS '{os}'");
        }
    };
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let arch = match arch.as_str() {
        "aarch64" => {
            if os == "darwin" {
                "arm64"
            } else {
                arch.as_str()
            }
        }
        _ => {
            panic!("unsupported target architecture '{arch}'");
        }
    };
    let new_name = lib_dir.join(format!("lib{lib_name}.{os}-{arch}.so"));

    os::unix::fs::symlink(dylib, &new_name).unwrap();

    Ok(())
}
