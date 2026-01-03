#[cfg(test)]
mod tests {
    use std::{env, process::Command};

    #[test]
    fn plugin_tests() {
        build();

        let dist = scratch::path("dist");

        let proptest_cases = env::var("PROPTEST_CASES").unwrap_or_else(|_| "50000".to_string());
        let proptest_verbose = env::var("PROPTEST_VERBOSE").unwrap_or_else(|_| "0".to_string());

        dbg!(&dist);
        let status = Command::new("zeek")
            // This loads the plugin from the parent crate.
            .env("ZEEK_PLUGIN_PATH", &dist)
            // Pass an empty input file so we exit immediately.
            .arg("/dev/null")
            .env("PROPTEST_CASES", proptest_cases)
            .env("PROPTEST_VERBOSE", proptest_verbose)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn build() {
        let status = Command::new("cargo")
            .args(["xtask", "build"])
            .status()
            .unwrap();
        assert!(status.success());
    }
}
