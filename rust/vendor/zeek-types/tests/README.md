Tests for `zeek-types`
======================

Usually Zeek does not ship with a library, but instead all plugins are assumed
to be loaded into a Zeek process. This means that anything using symbols
provided by Zeek is underlinked (the symbols only get resolved when loaded into
a Zeek process) and there is e.g., no easy way to set up normal test
executables.

The setup in this directory works around that so this crate can be
tested like users would expect with `cargo t`. This is accomplished with three
crates:

- `test-plugin/` is a crate which provides a Zeek plugin which executes
    hardcoded tests when loaded into Zeek. The dylib provided by the crate is
    underlinked.
- `runner/` is a crate consisting of a single test which prepares `test-plugin`
  as a Zeek plugin, and then loads it into a Zeek process. In this crate running
  `cargo t` runs the tests from `test-plugin`.
- `xtask` is a [xtask crate](https://github.com/matklad/cargo-xtask) so a crate
  can be prepared and lodaded as a Zeek plugin. It provides two commands:

  - `cargo xtask dist [CRATE]`: setup a plugin folder for the given crate.
    `runner` calls this with `test-plugin`.
  - `cargo xtask dist-dir`: print location of the prepared plugin

With that we can run `cargo t --workspace` to run the tests from the workspace root.

Running manually for debugging
------------------------------

Running the tests in a debugger is easier with manual loading.

1. Build tests

   ```console
   cargo xtask dist test-plugin
   ```

2. Load tests into Zeek. We load a script here so Zeek terminates after
   processing it, i.e., immediately. The plugin tests run after load without
   external trigger.

   ```console
   ZEEK_PLUGIN_PATH=$(cargo xtask dist-dir) zeek /dev/null
   ```

Customizing `proptest` setup
----------------------------

The test suite contains property tests implemented with
[`proptest`](https://proptest-rs.github.io/proptest/). The following
environment variables tweak its behavior:

- `PROPTEST_VERBOSE`: Verbosity, can be set to values between `0` and `2`.
- `PROPTEST_CASES`: Number of test cases to generate
