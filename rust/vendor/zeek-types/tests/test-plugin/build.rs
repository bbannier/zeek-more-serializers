use cargo_emit::{rerun_if_changed, rustc_link_arg};

fn main() {
    rerun_if_changed!("build.rs");

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
