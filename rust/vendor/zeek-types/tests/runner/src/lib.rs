#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, Stdio},
    };

    #[test]
    fn plugin_tests() {
        xtask(&["dist", "test-plugin"]);
        let dist_dir = xtask(&["dist-dir"]).trim().to_owned();

        let proptest_cases = env::var("PROPTEST_CASES").unwrap_or_else(|_| "10000".to_string());
        let proptest_verbose = env::var("PROPTEST_VERBOSE").unwrap_or_else(|_| "0".to_string());

        let status = Command::new("zeek")
            // Load the test plugin.
            .env("ZEEK_PLUGIN_PATH", &dist_dir)
            // Pass an empty input file so we exit immediately.
            .arg("/dev/null")
            .env("PROPTEST_CASES", proptest_cases)
            .env("PROPTEST_VERBOSE", proptest_verbose)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn xtask(args: &[&str]) -> String {
        let output = Command::new("cargo")
            .arg("xtask")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();

        eprintln!("{}", String::from_utf8(output.stderr).unwrap());
        assert!(output.status.success());

        String::from_utf8(output.stdout).unwrap()
    }
}
