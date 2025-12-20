use std::sync::LazyLock;

use ctor::ctor;
use cxx::UniquePtr;
use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};
use zeek_types::{Error, Val, support::PluginWrapper};

// Zeek expects plugins to be constructed on library load time. This function accomplishes that.
#[ctor]
fn init() {
    static _PLUGIN: LazyLock<TestPlugin> = LazyLock::new(TestPlugin::new);
    let _ = &*_PLUGIN;
}

type Result<T> = std::result::Result<T, Error>;

struct TestPlugin(#[allow(unused)] UniquePtr<PluginWrapper>);

impl TestPlugin {
    fn run_tests() {
        test_list();
        check_round_trip().unwrap();
    }

    fn new() -> Self {
        let mut plugin = PluginWrapper::new(env!("CARGO_PKG_NAME"), "plugin for testing");
        plugin.pin_mut().with_init_pre_execution(Self::run_tests);

        Self(plugin)
    }
}

fn check_round_trip() -> Result<()> {
    let mut runner = TestRunner::new(Config {
        test_name: Some("check_round_trip"),
        source_file: Some(std::file!()),
        ..Config::default()
    });

    let strategy = any::<Val<'static>>();

    runner
        .run(&strategy, |x0| {
            // We cannot create Zeek values from naked `None` values.
            if matches!(&x0, Val::None) {
                return Ok(());
            }

            let x = x0.to_valptr(None)?;
            let x = x.val().ok_or(Error::ValueUnset)?;
            let x1: Val = x.try_into()?;

            assert_eq!(x0, x1);
            Ok(())
        })
        .unwrap();

    println!("{runner}");

    Ok(())
}

fn test_list() {
    // Lists containing `None` are unsupported by Zeek.
    assert_eq!(
        Val::List(vec![Val::None]).to_valptr(None).err(),
        Some(Error::ValueUnset)
    );
    assert_eq!(
        Val::List(vec![Val::Bool(true), Val::None])
            .to_valptr(None)
            .err(),
        Some(Error::ValueUnset)
    );
}
