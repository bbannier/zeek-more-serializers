use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("no target OS selected");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("not target arch selected");

    println!("cargo:rustc-env=CARGO_CFG_TARGET_OS={target_os}");
    println!("cargo:rustc-env=CARGO_CFG_TARGET_ARCH={target_arch}");
}
