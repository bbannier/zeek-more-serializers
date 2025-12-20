use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    println!("cargo:rustc-env=CARGO_CFG_TARGET_OS={target_os}");
    println!("cargo:rustc-env=CARGO_CFG_TARGET_ARCH={target_arch}");
}
