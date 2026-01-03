use std::sync::LazyLock;

use ctor::ctor;
use cxx::UniquePtr;
use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};
use zeek_types::{Error, Val, support::PluginWrapper, zeek};

// Zeek expects plugins to be constructed on library load time. This function accomplishes that.
#[ctor]
fn init() {
    static _PLUGIN: LazyLock<TestPlugin> = LazyLock::new(|| TestPlugin::new());
    let _ = &*_PLUGIN;
}

type Result<T> = std::result::Result<T, Error>;

struct TestPlugin(#[allow(unused)] UniquePtr<PluginWrapper>);

impl TestPlugin {
    fn run_tests() {
        check_round_trip().unwrap();
    }

    fn new() -> Self {
        let mut plugin = PluginWrapper::new(env!("CARGO_PKG_NAME"), "plugin for testing");
        plugin.pin_mut().with_init_pre_execution(Self::run_tests);

        Self(plugin)
    }
}

fn type_info(val: &Val) -> Option<&'static zeek::TypePtr> {
    Some(match val {
        Val::Bool(..) => zeek::base_type(zeek::TypeTag::TYPE_BOOL),
        Val::Count(..) => zeek::base_type(zeek::TypeTag::TYPE_COUNT),
        Val::Int(..) => zeek::base_type(zeek::TypeTag::TYPE_INT),
        Val::Double(..) => zeek::base_type(zeek::TypeTag::TYPE_DOUBLE),
        Val::String(..) => zeek::base_type(zeek::TypeTag::TYPE_STRING),
        Val::Enum(..) => zeek::base_type(zeek::TypeTag::TYPE_ENUM),
        Val::Port { .. } => zeek::base_type(zeek::TypeTag::TYPE_PORT),
        Val::Addr(..) => zeek::base_type(zeek::TypeTag::TYPE_ADDR),
        Val::Subnet { .. } => zeek::base_type(zeek::TypeTag::TYPE_SUBNET),
        Val::Interval(..) => zeek::base_type(zeek::TypeTag::TYPE_INTERVAL),
        Val::Time(..) => zeek::base_type(zeek::TypeTag::TYPE_TIME),
        Val::Vec(..) => zeek::base_type(zeek::TypeTag::TYPE_VECTOR),
        Val::List(..) => zeek::base_type(zeek::TypeTag::TYPE_LIST),
        Val::Set(..) => zeek::base_type(zeek::TypeTag::TYPE_TABLE),
        Val::Table(..) => zeek::base_type(zeek::TypeTag::TYPE_TABLE),
        Val::Pattern { .. } => zeek::base_type(zeek::TypeTag::TYPE_PATTERN),
        Val::Record(..) => zeek::base_type(zeek::TypeTag::TYPE_RECORD),
        Val::None => None?,
    })
}

fn check_round_trip() -> Result<()> {
    let mut runner = TestRunner::new(Config {
        source_file: Some(std::file!()),
        ..Config::default()
    });

    let strategy = any::<Val<'static>>();

    runner
        .run(&strategy, |x0| {
            let Some(ty) = type_info(&x0) else {
                return Ok(());
            };
            let x = x0.to_valptr(Some(ty))?;
            let x = x.val().ok_or(Error::ValueUnset)?;
            let x1: Val = x.try_into()?;

            assert_eq!(x0, x1);
            Ok(())
        })
        .unwrap();

    Ok(())
}
