use std::{str::FromStr, sync::LazyLock};

use ctor::ctor;
use cxx::UniquePtr;
use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};
use zeek_types::{
    Error, IpNetwork, Val, arbitrary_val,
    support::PluginWrapper,
    types::{SetType, Type},
    zeek::TypeTag,
};

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
        vector();
        subnet();
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

    let strategy = any::<Type>()
        .prop_flat_map(|ty| arbitrary_val(ty.clone()).prop_map(move |val| (ty.clone(), val)));

    runner
        .run(&strategy, |(ty, x0)| {
            let ty: cxx::UniquePtr<_> = ty.try_into().expect("type should be compatible with Zeek");

            // We cannot create Zeek values from naked `None` values.
            assert!(!matches!(&x0, Val::None));

            let x = x0.clone().to_valptr(Some(&*ty))?;
            let x = x.val().ok_or(Error::ValueUnset)?;
            let x1: Val = x.try_into()?;

            assert_eq!(x0, x1);
            Ok(())
        })
        .unwrap();

    println!("{runner}");

    Ok(())
}

fn vector() {
    let ty: cxx::UniquePtr<_> = Type::Vec(Some(Box::new(Type::Count))).try_into().unwrap();
    assert_eq!(ty.val().unwrap().Tag(), TypeTag::TYPE_VECTOR);

    let val = Val::Vec(vec![Val::Count(42)]);
    let x0 = val.clone().to_valptr(Some(&ty)).unwrap();
    let x0 = x0.val().unwrap();
    let x1 = x0.try_into().unwrap();
    assert_eq!(val, x1);
}

fn subnet() {
    let ty: cxx::UniquePtr<_> = Type::Set(SetType(vec![Type::Subnet])).try_into().unwrap();

    let i = vec![Val::Subnet(IpNetwork::from_str("::/1").unwrap())].into_boxed_slice();

    let val = Val::Set(vec![i]);
    let x0 = val.clone().to_valptr(Some(&ty)).unwrap();
    let x1: Val = x0.val().unwrap().try_into().unwrap();
    assert_eq!(val, x1);
}
