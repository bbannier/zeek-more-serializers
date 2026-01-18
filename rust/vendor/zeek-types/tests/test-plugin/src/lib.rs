use std::{str::FromStr, sync::LazyLock};

use ctor::ctor;
use cxx::UniquePtr;
use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};
use zeek_types::{
    Error, IpNetwork, Subnet, Val, arbitrary_val,
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

struct TestPlugin(#[allow(unused)] UniquePtr<PluginWrapper>);

impl TestPlugin {
    fn run_tests() {
        vector();
        subnet();
        check_round_trip();
    }

    fn new() -> Self {
        let mut plugin = PluginWrapper::new(env!("CARGO_PKG_NAME"), "plugin for testing");
        plugin.pin_mut().with_init_pre_execution(Self::run_tests);

        Self(plugin)
    }
}

fn check_round_trip() {
    let mut runner = TestRunner::new(Config {
        test_name: Some("check_round_trip"),
        source_file: Some(std::file!()),
        ..Config::default()
    });

    let strategy = any::<Type>()
        .prop_flat_map(|ty| arbitrary_val(ty.clone()).prop_map(move |val| (ty.clone(), val)));

    runner
        .run(&strategy, |(ty, x0)| {
            {
                // Check type roundtrip. We ignore list types since Zeek has no list type.
                if !matches!(ty, Type::List(..)) {
                    let x: cxx::UniquePtr<_> = ty.clone().try_into()?;
                    let x1 = x.val().ok_or(Error::ValueUnset)?;
                    let x1: Type = x1.try_into()?;

                    assert_eq!(ty, x1);
                }

                // Check `Type::into_owned`.
                assert_eq!(ty.clone().into_owned(), ty);
            }

            let ty: cxx::UniquePtr<_> = ty
                .clone()
                .try_into()
                .expect("type should be compatible with Zeek");

            // We cannot create Zeek values from naked `None` values.
            assert!(!matches!(&x0, Val::None));

            {
                // Check value roundtrip.
                let x = x0.clone().to_valptr(Some(&*ty))?;
                let x = x.val().ok_or(Error::ValueUnset)?;
                let x1: Val = x.try_into()?;

                assert_eq!(x0, x1);
            }
            Ok(())
        })
        .unwrap();

    println!("{runner}");
}

fn vector() {
    let ty: cxx::UniquePtr<_> = Type::Vec(Box::new(Type::Count)).try_into().unwrap();
    assert_eq!(ty.val().unwrap().Tag(), TypeTag::TYPE_VECTOR);

    let val = Val::Vec(vec![Val::Count(42)]);
    let x0 = val.clone().to_valptr(Some(&ty)).unwrap();
    let x0 = x0.val().unwrap();
    let x1 = x0.try_into().unwrap();
    assert_eq!(val, x1);
}

fn subnet() {
    let ty: cxx::UniquePtr<_> = Type::Set(SetType(vec![Type::Subnet])).try_into().unwrap();

    let i = vec![Val::Subnet(Subnet::new(
        IpNetwork::from_str("::/1").unwrap(),
    ))]
    .into_boxed_slice();

    let val = Val::Set([i].into_iter().collect());
    let x0 = val.clone().to_valptr(Some(&ty)).unwrap();
    let x1: Val = x0.val().unwrap().try_into().unwrap();
    assert_eq!(val, x1);
}
