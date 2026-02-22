use std::{
    env,
    fs::{self, read_to_string},
    io::Write,
    os,
    path::PathBuf,
};

use anyhow::{Result, anyhow};
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

        /// Zeek scripts to include in the plugin's '__load__.zeek'.
        #[arg(short, long)]
        defs: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::DistDir => dist_dir(),
        Command::Dist { plugin, defs } => dist(plugin, defs),
    }
}

fn dist_dir() -> Result<()> {
    let dist = scratch::path("dist");
    let dist = dist
        .to_str()
        .ok_or(anyhow!("path '{dist:?}' is not valid UTF-8"))?;
    println!("{dist}");

    Ok(())
}

fn dist(package: String, defs: Vec<PathBuf>) -> Result<()> {
    // Build the package.
    std::process::Command::new("cargo")
        .args(["build", "--package", &package])
        .status()?;

    let out_dir: PathBuf = env!("OUT_DIR").into();

    let dist = scratch::path("dist");

    // Write the marker file.
    let marker = dist.join("__zeek_plugin__");
    let _ = fs::remove_file(&marker);
    fs::write(&marker, format!("{package}\n"))?;

    // Put a link to the library in the expected spot with expected name.
    let lib_dir = dist.join("lib");
    let _ = fs::remove_dir_all(&lib_dir);
    fs::create_dir(&lib_dir)?;
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
    let os = env::var("CARGO_CFG_TARGET_OS")?;
    let os = match os.as_str() {
        "macos" => "darwin",
        "linux" => "linux",
        _ => {
            panic!("unsupported target OS '{os}'");
        }
    };
    let arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let arch = match arch.as_str() {
        "aarch64" => {
            if os == "darwin" {
                "arm64"
            } else {
                arch.as_str()
            }
        }
        "x86_64" => arch.as_str(),
        _ => {
            panic!("unsupported target architecture '{arch}'");
        }
    };
    let new_name = lib_dir.join(format!("lib{lib_name}.{os}-{arch}.so"));

    os::unix::fs::symlink(dylib, &new_name)?;

    // If needed, generate a `__load__.zeek`.
    // FIXME(bbannier): These files should be created automatically, e.g., from a proc macro and
    // just be collected here without having to be passed explicitly.
    if !defs.is_empty() {
        let bif_dir = lib_dir.join("bif");
        fs::create_dir(&bif_dir)?;

        let mut load = fs::File::create_new(bif_dir.join("__load__.zeek"))?;

        for f in defs {
            let contents = read_to_string(f)?;
            load.write_all(contents.as_bytes())?;
        }
    }

    Ok(())
}
