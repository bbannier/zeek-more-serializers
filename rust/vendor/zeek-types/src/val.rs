use crate::{UniquePtr, ffi::zeek_id_find_type, wrap_unsafe};
use core::slice;
use derivative::Derivative;
use ipnetwork::IpNetwork;
use num_traits::cast::FromPrimitive;

#[cfg(feature = "proptest")]
use proptest::prelude::{Arbitrary, BoxedStrategy};

use std::{borrow::Cow, collections::BTreeMap, net::IpAddr};

use time::{Duration, OffsetDateTime};

use crate::{Error, Result, TransportProto, ffi};

/// Trait so we code can work with both `ffi::Val` and `ffi::ZVal`.
pub trait ValInterface {
    #![allow(non_snake_case)]
    fn as_bool(&self) -> bool;
    fn as_int(&self) -> i64;
    fn as_count(&self) -> u64;
    fn as_double(&self) -> f64;
    fn as_interval(&self) -> f64;
    fn as_time(&self) -> f64;
    fn as_string_val(&self) -> Option<&ffi::StringVal>;
    fn as_port_val(&self) -> Option<&ffi::PortVal>;
    fn as_addr_val(&self) -> Option<&ffi::AddrVal>;
    fn as_subnet_val(&self) -> Option<&ffi::SubNetVal>;
    fn as_vector_val(&self) -> Option<&ffi::VectorVal>;
    fn as_enum(&self) -> Result<u64>;
    fn as_pattern_val(&self) -> Option<&ffi::PatternVal>;
    fn as_table_val(&self) -> Option<&ffi::TableVal>;
    fn as_record_val(&self) -> Option<&ffi::RecordVal>;
    fn as_list_val(&self) -> Option<&ffi::ListVal>;
    fn as_any(&self) -> Option<&ffi::Val>;
}

/// Helper trait to convert a `Val` given some tag. We use this to
/// provide blanket impls for any type implementing `ValInterface`.
pub trait ValConvert<T>: Sized {
    type Error;
    fn convert(val: T, type_: &ffi::Type) -> Result<Self>;
}

impl<'a, T: ValInterface> ValConvert<&'a T> for Val<'a> {
    type Error = Error;

    #[allow(clippy::too_many_lines)]
    fn convert(val: &'a T, type_: &ffi::Type) -> Result<Self> {
        use ffi::TypeTag;

        let tag = type_.Tag();

        Ok(match tag {
        TypeTag::TYPE_VOID => Self::None,
        TypeTag::TYPE_BOOL => Self::Bool(val.as_bool()),
        TypeTag::TYPE_INT => Self::Int(val.as_int()),
        TypeTag::TYPE_COUNT => Self::Count(val.as_count()),
        TypeTag::TYPE_DOUBLE => Self::Double(val.as_double()),
        TypeTag::TYPE_STRING => {
            let s = val.as_string_val().ok_or(Error::ValueUnset)?;
            let len = usize::try_from(s.Len()).map_err(Error::IntegerConversion)?;
            let xs = match len {
                0 => &[],
                _ => unsafe { slice::from_raw_parts(s.Bytes(), len) },
            };

            Self::String(xs.into())
        }
        TypeTag::TYPE_PORT => {
            let p = val.as_port_val().ok_or(Error::ValueUnset)?;
            Self::Port {
                num: p.Port(),
                proto: p.PortType().try_into()?,
            }
        }
        TypeTag::TYPE_ADDR => {
            let addr = val.as_addr_val().ok_or(Error::ValueUnset)?;
            Self::Addr(addr.try_into()?)
        }
        TypeTag::TYPE_SUBNET => {
            let sub = val.as_subnet_val().ok_or(Error::ValueUnset)?;
            let sub = ffi::Subnet::from(sub);
            let network = IpNetwork::new(sub.prefix.try_into()?, sub.width.try_into()?)?;
            Self::Subnet(network)
        }
        TypeTag::TYPE_INTERVAL => {
            let secs = val.as_interval();
            Self::Interval(Duration::seconds_f64(secs))
        }
        TypeTag::TYPE_TIME => {
            let offset_secs = val.as_time();
            let offset_ns = i128::from_f64(offset_secs * 1e9).ok_or(Error::UnrepresentableTimeOffsetDouble(offset_secs))?;
            Self::Time(OffsetDateTime::from_unix_timestamp_nanos(offset_ns)?)
        }
        TypeTag::TYPE_VECTOR => {
            let xs = val.as_vector_val().ok_or(Error::ValueUnset)?;

            let xs: Result<_> = xs
                .into_iter()
                .map(|x| {
                    // TODO(bbannier): why does `x.try_into()` not work here?
                    x.value().map_or(Ok(Val::None), |v| ValConvert::convert(v, x.type_().ok_or(Error::ValueUnset)?))
                })
                .collect();

            Self::Vec(xs?)
        }

        TypeTag::TYPE_ENUM => {
            let type_ = type_.as_enum_type().ok_or(Error::ValueUnset)?;
            Self::Enum(TypeId(type_.GetName().to_string().into()), val.as_enum()?)
        },

        TypeTag::TYPE_PATTERN => {
            let val = val.as_pattern_val().ok_or(Error::ValueUnset)?;
            let pat = val.as_pattern() .ok_or(Error::ValueUnset)?;

            let exact = pat.pattern_text()?.into();
            let anywhere = pat.anywhere_pattern_text()?.into();

            Self::Pattern{ exact, anywhere }
        }

        TypeTag::TYPE_TABLE => {
            let val = val.as_table_val().ok_or(Error::ValueUnset)?;
            let it = val.iter();
            let it = it.as_ref().ok_or(Error::ValueUnset)?;
            let xs: Result<Vec<_>> = std::iter::from_fn(move || {
                let val = it.next();
                // `next` returns a set pointer until the range is exhausted.
                let cur = val.as_ref()?;

                // This way of table iteration returns a value, not a reference, so we need to
                // transform the `Val` into owned variants.
                //
                // TODO(bbannier): Figure out a way to iterate tables which returns references
                // so we can avoid the copy.

                let key: Result<Vec<Val>> = cur.key().try_into();
                let key = key.map(|x| x.into_iter().map(Val::into_owned).collect());

                let val =  cur.value_ref().map_or(Ok(Val::None), TryInto::try_into);

                Some((key, val))
            }).map(|(k, v)| Ok((k?, v?)))
            .collect();

            if type_.IsSet() {
                let xs = xs?.into_iter().map(|(k, _)| k).collect();
                Val::Set(xs)
            } else {
                Val::Table(xs?)
            }
        }

        TypeTag::TYPE_RECORD => {
            let val = val.as_record_val().ok_or(Error::ValueUnset)?;

            let ty = val.GetType().val().ok_or(Error::ValueUnset)?;
            let ty = ty.as_record_type() .ok_or(Error::ValueUnset)?;

            let fields: Result<_> = (0..ty.NumFields())
                .filter_map(|i| {
                    let name = ty.field_name(i)?;
                    Some((i, name))
                })
                .map(|(i, name)| {
                    let name = name?.into();

                    let val_ = val.get_field(i);

                    // TODO(bbannier): why does `x.try_into()` not work here?
                    let val = val_.value().map_or(Ok(Val::None), |v| ValConvert::convert(v, val_.type_().ok_or(Error::ValueUnset)?))?;

                    Ok((name, val))
                }).collect();

            let name = ty.GetName().to_string();

            Self::Record(TypeId(name.into()), fields?)
        }

        TypeTag::TYPE_LIST => {
            let val = val.as_list_val().ok_or(Error::ValueUnset)?;
            Self::List(val.try_into()?)
        }

        TypeTag::TYPE_ANY => {
            let val = val.as_any().ok_or(Error::ValueUnset)?;
            val.try_into()?
        }

        TypeTag::TYPE_OPAQUE
        // TODO(bbannier): These we should be able to support in principle.
        | TypeTag::TYPE_FUNC
        | TypeTag::TYPE_FILE
        | TypeTag::TYPE_TYPE
        | TypeTag::TYPE_ERROR => Err(Error::UnsupportedTypeTag(type_.Tag()))?,

        _ => Err(Error::UnknownTypeTag(type_.Tag()))?,
    })
    }
}

/// Rust wrapper around `zeek::Val`.
#[allow(clippy::unsafe_derive_deserialize)] // Fires incorrectly, FP.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Derivative)]
#[derivative(PartialEq)]
#[derive(Debug, Clone)]
pub enum Val<'a> {
    None,
    Bool(bool),
    Count(u64),
    Int(i64),
    Double(f64),
    Enum(TypeId<'a>, u64),
    String(Cow<'a, [u8]>),
    Port {
        num: u32,
        proto: TransportProto,
    },
    // Use custom comparison function for special handling of mapped IPv6 addresses.
    Addr(#[derivative(PartialEq(compare_with = "compare_ipaddr"))] IpAddr),
    // Use custom comparison function since `IpNetwork` by default compares for bit equality, but
    // we want equivalence.
    Subnet(#[derivative(PartialEq(compare_with = "compare_ipnetwork"))] IpNetwork),
    Interval(Duration),
    Time(OffsetDateTime),
    Vec(Vec<Val<'a>>),
    List(Vec<Val<'a>>),
    Set(Vec<Vec<Val<'a>>>),
    Table(Vec<(Vec<Val<'a>>, Val<'a>)>),
    Pattern {
        exact: Cow<'a, str>,
        anywhere: Cow<'a, str>,
    },
    Record(TypeId<'a>, BTreeMap<Cow<'a, str>, Val<'a>>),
}

impl<'a> Val<'a> {
    /// Convert the value into a Zeek value pointer.
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion of the value or any of its parts fail.
    #[allow(clippy::too_many_lines)]
    pub fn to_valptr(&'a self, ty: Option<&'a ffi::TypePtr>) -> Result<UniquePtr<ffi::ValPtr>> {
        // We need special treatment for deserializing to an `any` since we might not have enough
        // type information (e.g., for empty containers)
        //
        // TODO(bbannier): Ideally we wouldn't need to look at the dest type `ty` here at all, but
        // unfortunately Zeek requires more typing than we would like.
        //
        // TODO(bbannier): Revisit this once treatment of empty containers improves in Zeek, see
        // https://github.com/zeek/zeek/issues/5114 and https://github.com/zeek/zeek/issues/5115.
        let ty = ty
            .map(ffi::TypePtr::val)
            .ok_or(Error::InsufficientTypeInformation)?;

        let ty = ty.and_then(|ty| {
            if ty.Tag() == ffi::TypeTag::TYPE_ANY {
                None
            } else {
                Some(ty)
            }
        });

        Ok(match self {
            Val::None => ffi::make_null(),
            Val::Bool(x) => ffi::make_bool(*x),
            Val::Count(x) => ffi::make_count(*x),
            Val::Int(x) => ffi::make_int(*x),
            Val::Double(x) => ffi::make_double(*x),
            Val::String(x) => ffi::make_string(x),
            Val::Pattern { exact, anywhere } => ffi::make_pattern(exact, anywhere),
            Val::Interval(x) => ffi::make_interval(x.as_seconds_f64()),
            Val::Time(x) => {
                let offset_ns = x.unix_timestamp_nanos();
                let offset_ns = f64::from_i128(offset_ns)
                    .ok_or(Error::UnrepresentableTimeOffsetNanos(offset_ns))?;
                let secs = offset_ns / 1e9;
                ffi::make_time(secs)
            }
            Val::Vec(xs) => {
                let yield_ = ty
                    .and_then(ffi::Type::as_vector_type)
                    .map(ffi::VectorType::Yield);

                let mut vals = ffi::ValPtrVector::make();

                for x in xs {
                    vals.pin_mut().push(x.to_valptr(yield_)?);
                }

                ffi::make_vector(vals)
            }
            Val::Addr(x) => ffi::make_addr(&x.to_string()),
            Val::Subnet(x) => ffi::make_subnet(&x.network().to_string(), x.prefix()),
            Val::Enum(name, x) => {
                let ty = zeek_id_find_type(&name.0)
                    .val()
                    .ok_or(Error::UnknownType(name.0.to_string()))?;

                let ty = ty
                    .as_enum_type()
                    .ok_or_else(|| Error::UnexpectedTypeDefinition {
                        type_: name.0.to_string(),
                        expected: ffi::TypeTag::TYPE_ENUM,
                        actual: ty.Tag(),
                    })?;
                ffi::make_enum(*x, ty)
            }
            Val::Port { num, proto } => ffi::make_port(*num, (*proto).into()),
            Val::Record(name, fields) => {
                let ty = zeek_id_find_type(&name.0)
                    .val()
                    .ok_or(Error::UnknownType(name.0.to_string()))?;
                let ty = ty
                    .as_record_type()
                    .ok_or_else(|| Error::UnexpectedTypeDefinition {
                        type_: name.0.to_string(),
                        expected: ffi::TypeTag::TYPE_RECORD,
                        actual: ty.Tag(),
                    })?;

                let (names, data): (Vec<_>, Vec<_>) = fields
                    .iter()
                    .filter_map(|(k, v)| {
                        let k: &str = k;
                        let ty = ty.get_field_type(k)?;
                        let v = v.to_valptr(Some(ty));

                        Some((k, v))
                    })
                    .unzip();

                let mut result = ffi::ValPtrVector::make();
                for x in data {
                    result.pin_mut().push(x?);
                }

                ffi::make_record(&names, result, ty)?
            }
            Val::List(xs) => {
                let tys = ty
                    .and_then(|ty| {
                        if ty.Tag() == ffi::TypeTag::TYPE_LIST {
                            ty.as_type_list()
                        } else {
                            None
                        }
                    })
                    .map(ffi::TypeList::GetTypes);

                if let Some(tys) = tys
                    && xs.len() != tys.len()
                {
                    Err(Error::InconsistentTableIndex {
                        expected: tys.len(),
                        actual: xs.len(),
                    })?;
                }

                let mut vals = ffi::ValPtrVector::make();

                for (i, x) in xs.iter().enumerate() {
                    let ty = tys.and_then(|ty| ty.get(i));
                    vals.pin_mut().push(x.to_valptr(ty)?);
                }

                ffi::make_list(vals)
            }
            Val::Set(xs) => {
                let ty = ty
                    .and_then(|ty| {
                        if ty.Tag() == ffi::TypeTag::TYPE_TABLE {
                            ty.as_table_type()
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::ValueUnset)?;

                let mut keys = ffi::ValPtrVector::make();
                let index_types = ty.GetIndexTypes();
                for ks in xs {
                    if ks.len() != index_types.len() {
                        Err(Error::InconsistentTableIndex {
                            expected: index_types.len(),
                            actual: ks.len(),
                        })?;
                    }

                    let mut ks_ = ffi::ValPtrVector::make();
                    for (k, ty) in ks.iter().zip(index_types) {
                        ks_.pin_mut().push(k.to_valptr(Some(ty))?);
                    }

                    keys.pin_mut().push(ffi::make_list(ks_));
                }

                ffi::make_set(keys, ty)
            }
            Val::Table(xs) => {
                let ty = ty
                    .and_then(|ty| {
                        if ty.Tag() == ffi::TypeTag::TYPE_TABLE {
                            ty.as_table_type()
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::ValueUnset)?;

                let mut keys = ffi::ValPtrVector::make();
                let mut values = ffi::ValPtrVector::make();

                let yield_type = ty.Yield();
                let index_types = ty.GetIndexTypes();

                for (ks, v) in xs {
                    if ks.len() != index_types.len() {
                        Err(Error::InconsistentTableIndex {
                            expected: index_types.len(),
                            actual: ks.len(),
                        })?;
                    }

                    let mut ks_ = ffi::ValPtrVector::make();
                    for (k, ty) in ks.iter().zip(index_types) {
                        ks_.pin_mut().push(k.to_valptr(Some(ty))?);
                    }

                    keys.pin_mut().push(ffi::make_list(ks_));
                    values.pin_mut().push(v.to_valptr(Some(yield_type))?);
                }

                ffi::make_table(keys, values, ty)
            }
        })
    }

    /// Convert this `Val` into an owned version.
    pub fn into_owned(self) -> Val<'static> {
        match self {
            Val::String(x) => Val::String(Cow::from(x.into_owned())),
            Val::Vec(x) => Val::Vec(x.into_iter().map(Val::into_owned).collect()),
            Val::List(x) => Val::List(x.into_iter().map(Val::into_owned).collect()),
            Val::Set(x) => Val::Set(
                x.into_iter()
                    .map(|k| k.into_iter().map(Val::into_owned).collect())
                    .collect(),
            ),
            Val::Table(x) => Val::Table(
                x.into_iter()
                    .map(|(k, v)| {
                        let k = k.into_iter().map(Val::into_owned).collect();
                        let v = v.into_owned();

                        (k, v)
                    })
                    .collect(),
            ),
            Val::Pattern { exact, anywhere } => {
                let exact = Cow::from(exact.into_owned());
                let anywhere = Cow::from(anywhere.into_owned());

                Val::Pattern { exact, anywhere }
            }
            Val::Record(name, x) => {
                let name = TypeId(Cow::from(name.0.into_owned()));
                let x = x
                    .into_iter()
                    .map(|(k, v)| (Cow::from(k.into_owned()), v.into_owned()));

                Val::Record(name, x.collect())
            }
            Val::Enum(id, x) => Val::Enum(TypeId(Cow::from(id.0.into_owned())), x),

            // For the remaining variants we can simply pass the data through.
            Val::None => Val::None,
            Val::Bool(x) => Val::Bool(x),
            Val::Count(x) => Val::Count(x),
            Val::Int(x) => Val::Int(x),
            Val::Double(x) => Val::Double(x),
            Val::Port { num, proto } => Val::Port { num, proto },
            Val::Addr(x) => Val::Addr(x),
            Val::Subnet(x) => Val::Subnet(x),
            Val::Interval(x) => Val::Interval(x),
            Val::Time(x) => Val::Time(x),
        }
    }
}

impl<'a> TryFrom<&'a ffi::Val> for Val<'a> {
    type Error = Error;

    fn try_from(val: &'a ffi::Val) -> Result<Self> {
        let type_ = val.GetType().val().ok_or(Error::ValueUnset)?;
        <Val<'a> as ValConvert<&ffi::Val>>::convert(val, type_)
    }
}

impl<'a> TryFrom<&'a ffi::ListVal> for Vec<Val<'a>> {
    type Error = Error;

    fn try_from(value: &'a ffi::ListVal) -> Result<Self> {
        let len = usize::try_from(value.Length())?;
        (0..len)
            .map(|i| value.Idx(i).val().ok_or(Error::ValueUnset)?.try_into())
            .collect()
    }
}

fn compare_ipnetwork(a: &IpNetwork, b: &IpNetwork) -> bool {
    compare_ipaddr(&a.network(), &b.network()) && a.prefix() == b.prefix()
}

fn compare_ipaddr(a: &IpAddr, b: &IpAddr) -> bool {
    fn make_canonical(addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(..) => v4,
        }
    }

    make_canonical(*a) == make_canonical(*b)
}

impl ValInterface for ffi::Val {
    wrap_unsafe!(as_string_val, AsStringVal, ffi::StringVal);
    wrap_unsafe!(as_port_val, AsPortVal, ffi::PortVal);
    wrap_unsafe!(as_addr_val, AsAddrVal, ffi::AddrVal);
    wrap_unsafe!(as_subnet_val, AsSubNetVal, ffi::SubNetVal);
    wrap_unsafe!(as_vector_val, AsVectorVal, ffi::VectorVal);
    wrap_unsafe!(as_table_val, AsTableVal, ffi::TableVal);
    wrap_unsafe!(as_pattern_val, AsPatternVal, ffi::PatternVal);
    wrap_unsafe!(as_record_val, AsRecordVal, ffi::RecordVal);
    wrap_unsafe!(as_list_val, AsListVal, ffi::ListVal);

    fn as_any(&self) -> Option<&ffi::Val> {
        Some(self)
    }

    fn as_enum(&self) -> Result<u64> {
        let val = unsafe { self.AsEnumVal().as_ref() }.ok_or(Error::ValueUnset)?;
        let val = ffi::enum_size_val(val);

        let val = val.val().ok_or(Error::ValueUnset)?;
        let type_ = val.GetType().val().ok_or(Error::ValueUnset)?;

        let expected = ffi::TypeTag::TYPE_COUNT;
        let actual = type_.Tag();
        if expected != actual {
            return Err(Error::MismatchingType { expected, actual });
        }

        Ok(val.AsCount())
    }

    fn as_bool(&self) -> bool {
        self.AsBool()
    }

    fn as_int(&self) -> i64 {
        self.AsInt()
    }

    fn as_count(&self) -> u64 {
        self.AsCount()
    }

    fn as_double(&self) -> f64 {
        self.AsDouble()
    }

    fn as_interval(&self) -> f64 {
        self.AsInterval()
    }

    fn as_time(&self) -> f64 {
        self.AsTime()
    }
}

// Identifier of a custom Zeek type.
//
// NOTE: Ideally we'd have some cheap-to-copy ID like a `u64` directly from Zeek to refer to custom
// types, but this doesn't seem to exist. The value here is static, but depending on the identifier
// length might require considerable space.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TypeId<'a>(Cow<'a, str>);

impl<'a> TypeId<'a> {
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
        todo!()
    }
}

#[cfg(feature = "proptest")]
impl Arbitrary for Val<'static> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use ipnetwork::{Ipv4Network, Ipv6Network};
        use proptest::prelude::*;

        prop_oneof![
            Just(Val::None),
            any::<bool>().prop_map(Val::Bool),
            any::<u64>().prop_map(Val::Count),
            any::<i64>().prop_map(Val::Int),
            any::<f64>().prop_map(Val::Double),
            ("Notice::Type", 0..32u64).prop_map(|(id, n)| Val::Enum(TypeId::new(id), n)),
            any::<Vec<u8>>().prop_map(|x| Val::String(x.into())),
            (any::<u16>(), any::<TransportProto>()).prop_map(|(num, proto)| Val::Port {
                num: num.into(), // FIXME(bbannier): constrain this on the type level.
                proto
            }),
            any::<IpAddr>().prop_map(Val::Addr),
            (any::<Ipv4Addr>(), 0..=32u8)
                .prop_filter_map("invalid ipv4 address", |(addr, prefix)| {
                    Some(Val::Subnet(IpNetwork::V4(
                        Ipv4Network::new(addr, prefix).ok()?,
                    )))
                })
                .boxed(),
            (any::<Ipv6Addr>(), 0..=32u8).prop_filter_map(
                "invalid ipv6 address",
                |(addr, prefix)| Some(Val::Subnet(IpNetwork::V6(
                    Ipv6Network::new(addr, prefix).ok()?
                )))
            ),
            (-1_000_000..=1_000_000i64, any::<i32>()).prop_map(|(s, ns)| {
                // Limit seconds range since Zeek interval loose precision near the edges of range.
                Val::Interval(Duration::new(s, ns))
            }),
            (-1_000..1_000_000_000i64).prop_filter_map("invalid timestamp", |x| {
                // Limit time range since Zeek time looses precision near edges of range.
                Some(Val::Time(OffsetDateTime::from_unix_timestamp(x).ok()?))
            }),
            // FIXME(bbannier): implement these as well.
            // prop::collection::vec(any::<Val>(), 0..1024).prop_map(|x| Val::Vec(x)),
            // prop::collection::vec(val_strategy(), 0..1024).prop_map(|x| Val::List(x)),
            // Just(Val::Set(todo!())),
            // Just(Val::Table(todo!())),
            // Just(Val::Pattern {
            //     exact: todo!(),
            //     anywhere: todo!()
            // }),
            // Just(Val::Record(todo!(), todo!())),
        ]
        .boxed()
    }
}

#[cfg(feature = "proptest")]
impl Arbitrary for TransportProto {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        prop_oneof![
            Just(TransportProto::Unknown),
            Just(TransportProto::Tcp),
            Just(TransportProto::Udp),
            Just(TransportProto::Icmp),
        ]
        .boxed()
    }
}
