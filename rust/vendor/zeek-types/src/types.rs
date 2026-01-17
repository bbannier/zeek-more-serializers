use std::borrow::Cow;

/// Identifier of a custom Zeek type.
//
// NOTE: Ideally we'd have some cheap-to-copy ID like a `u64` directly from Zeek to refer to custom
// types, but this doesn't seem to exist. The value here is static, but depending on the identifier
// length might require considerable space.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TypeId<'a>(Cow<'a, str>);

impl<'a> TypeId<'a> {
    #[must_use]
    pub fn new<S>(name: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        Self(name.into())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

impl TypeId<'_> {
    #[must_use]
    pub fn into_owned(self) -> TypeId<'static> {
        TypeId(Cow::from(self.0.into_owned()))
    }
}

#[cfg(feature = "proptest")]
mod proptest_tools {
    use crate::types::TypeId;
    use {
        crate::{Error, ffi, support, zeek},
        proptest::prelude::*,
    };

    /// Model for `zeek::Type`.
    ///
    #[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
    pub enum Type<'a> {
        Bool,
        Count,
        Int,
        Double,
        String,
        Port,
        Addr,
        Subnet,
        Interval,
        Time,
        Pattern,
        Vec(Option<Box<Type<'a>>>),
        List(Option<Box<Type<'a>>>),
        Set(SetType<'a>),
        Table(TableType<'a>),
        Enum(TypeId<'a>),
        Record(TypeId<'a>),
    }

    impl Type<'_> {
        fn into_owned(self) -> Type<'static> {
            match self {
                Type::Bool => Type::Bool,
                Type::Count => Type::Count,
                Type::Int => Type::Int,
                Type::Double => Type::Double,
                Type::String => Type::String,
                Type::Port => Type::Port,
                Type::Addr => Type::Addr,
                Type::Subnet => Type::Subnet,
                Type::Interval => Type::Interval,
                Type::Time => Type::Time,
                Type::Pattern => Type::Pattern,
                Type::Vec(xs) => Type::Vec(xs.map(|x| Box::new((*x).into_owned()))),
                Type::List(xs) => Type::List(xs.map(|x| Box::new((*x).into_owned()))),
                Type::Set(xs) => Type::Set(xs.into_owned()),
                Type::Table(xs) => Type::Table(xs.into_owned()),
                Type::Enum(id) => Type::Enum(id.into_owned()),
                Type::Record(id) => Type::Record(id.into_owned()),
            }
        }
    }

    impl TryFrom<Type<'_>> for cxx::UniquePtr<zeek::TypePtr> {
        type Error = Error;

        fn try_from(value: Type<'_>) -> Result<Self, Self::Error> {
            Ok(match value {
                Type::Bool => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_BOOL)),
                Type::Count => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_COUNT)),
                Type::Int => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_INT)),
                Type::Double => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_DOUBLE)),
                Type::String => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_STRING)),
                Type::Port => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_PORT)),
                Type::Addr => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_ADDR)),
                Type::Subnet => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_SUBNET)),
                Type::Interval => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_INTERVAL)),
                Type::Time => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_TIME)),
                Type::Pattern => ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_PATTERN)),

                Type::Record(id) | Type::Enum(id) => {
                    ffi::to_owned_type(support::zeek_id_find_type(id.name()))
                }

                Type::Vec(x) => {
                    let inner = x.map_or_else(
                        // We can encode unknown vector yield type as `TYPE_ANY`.
                        || Ok(ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_ANY))),
                        |x| (*x).try_into(),
                    )?;
                    ffi::make_vector_type(&inner)
                }

                Type::List(x) => {
                    let x = x.ok_or(Error::InsufficientTypeInformation)?;
                    (*x).try_into()?
                }

                Type::Set(x) => {
                    let x: cxx::UniquePtr<_> = x.try_into()?;
                    assert!(!x.is_null()); // We never create an unset `unique_ptr` here.
                    x
                }

                Type::Table(x) => {
                    let x: cxx::UniquePtr<_> = x.try_into()?;
                    assert!(!x.is_null()); // We never create an unset `unique_ptr` here.
                    x
                }
            })
        }
    }

    impl TryFrom<&zeek::Type> for Type<'static> {
        type Error = Error;

        fn try_from(value: &zeek::Type) -> Result<Self, Self::Error> {
            use zeek::TypeTag;
            let tag = value.Tag();

            Ok(match tag {
                TypeTag::TYPE_BOOL => Type::Bool,
                TypeTag::TYPE_COUNT => Type::Count,
                TypeTag::TYPE_INT => Type::Int,
                TypeTag::TYPE_DOUBLE => Type::Double,
                TypeTag::TYPE_STRING => Type::String,
                TypeTag::TYPE_PORT => Type::Port,
                TypeTag::TYPE_ADDR => Type::Addr,
                TypeTag::TYPE_SUBNET => Type::Subnet,
                TypeTag::TYPE_INTERVAL => Type::Interval,
                TypeTag::TYPE_TIME => Type::Time,
                TypeTag::TYPE_PATTERN => Type::Pattern,
                TypeTag::TYPE_VECTOR => todo!(),
                TypeTag::TYPE_TABLE => todo!(),
                TypeTag::TYPE_ENUM => todo!(),
                TypeTag::TYPE_RECORD => todo!(),
                _ => Err(Error::UnknownTypeTag(tag))?,
            })
        }
    }

    impl Arbitrary for Type<'static> {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            let leaf = prop_oneof![
                Just(Type::Bool),
                Just(Type::Count),
                Just(Type::Int),
                Just(Type::Double),
                Just(Type::String),
                Just(Type::Port),
                Just(Type::Addr),
                Just(Type::Subnet),
                Just(Type::Interval),
                Just(Type::Time),
                Just(Type::Pattern),
                Just(Type::Enum(TypeId::new("Notice::Type"))),
                // TODO(bbannier): Implement record testing.
                // Just(Type::Record(TypeId::new("SumStats::SumStat"))),
            ];

            prop_oneof![
                leaf.clone(),
                leaf.clone().prop_recursive(4, 4, 8, |inner| {
                    // List does not support `any`.
                    inner.prop_map(Box::new).prop_map(Some).prop_map(Type::List)
                }),
                leaf.clone()
                    .prop_filter("addrs in set have special semantics", |x| !matches!(
                        x,
                        Type::Addr
                    ))
                    .prop_filter("patterns in sets have special semantics", |x| !matches!(
                        x,
                        Type::Pattern { .. }
                    ))
                    .prop_filter("double in sets are hard", |x| !matches!(x, Type::Double))
                    .prop_recursive(4, 4, 8, |inner| {
                        prop::collection::vec(inner, 1..4usize)
                            .prop_map(SetType)
                            .prop_map(Type::Set)
                    }),
                // TODO(bbannier): implement generating table values in `arbitrary_val`.
                // leaf.clone().prop_recursive(4, 4, 8, |inner| {
                //     let key = prop::collection::vec(inner.clone(), 1..4usize);
                //     let value = prop::option::weighted(0.8, inner.prop_map(Box::new));

                //     // Always generated typed table types.
                //     (key, value).prop_filter_map("table of any is unsupported", |(k, v)| {
                //         let v = v?;
                //         let tt = TableType(k, Some(v));
                //         Some(Type::Table(tt))
                //     })
                // }),
                // TODO(bbannier): Test `vector of any`, i.e., the `None` variant here.
                leaf.clone()
                    .prop_map(|inner| { Type::Vec(Some(Box::new(inner))) }),
            ]
            .boxed()
        }
    }

    #[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
    pub struct SetType<'a>(pub Vec<Type<'a>>);

    impl SetType<'_> {
        #[must_use]
        pub fn into_owned(self) -> SetType<'static> {
            SetType(self.0.into_iter().map(Type::into_owned).collect())
        }
    }

    impl TryFrom<SetType<'_>> for cxx::UniquePtr<zeek::TypePtr> {
        type Error = Error;

        fn try_from(SetType(xs): SetType<'_>) -> Result<Self, Self::Error> {
            let mut keys = support::TypePtrVector::make(xs.len());
            for x in xs {
                let x: cxx::UniquePtr<_> = x.try_into()?;
                assert!(!x.is_null());
                keys.pin_mut().push(x);
            }

            Ok(ffi::make_table_type(keys, cxx::UniquePtr::null()))
        }
    }

    impl TryFrom<TableType<'_>> for cxx::UniquePtr<zeek::TypePtr> {
        type Error = Error;

        fn try_from(TableType(keys_, vals): TableType) -> Result<Self, Self::Error> {
            let mut keys = support::TypePtrVector::make(keys_.len());
            for x in keys_ {
                let x: cxx::UniquePtr<_> = x.try_into()?;
                assert!(!x.is_null());
                keys.pin_mut().push(x);
            }

            let vals = vals.map_or_else(
                // We can encode unknown table element type as `TYPE_ANY`.
                || Ok(ffi::to_owned_type(zeek::base_type(zeek::TypeTag::TYPE_ANY))),
                |v| (*v).try_into(),
            )?;

            Ok(ffi::make_table_type(keys, vals))
        }
    }

    #[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
    // In contrast to table keys which always have a concrete type, table values can be `any` and not
    // knowing their type is okay.
    pub struct TableType<'a>(pub Vec<Type<'a>>, pub Option<Box<Type<'a>>>);

    impl TableType<'_> {
        fn into_owned(self) -> TableType<'static> {
            let TableType(key, value) = self;

            let key = key.into_iter().map(Type::into_owned).collect();
            let value = value.map(|x| Box::new((*x).into_owned()));

            TableType(key, value)
        }
    }
}

#[cfg(feature = "proptest")]
pub use proptest_tools::{SetType, TableType, Type};
