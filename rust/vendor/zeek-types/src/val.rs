use crate::{UniquePtr, wrap_unsafe, zeek};
use core::slice;
use ipnetwork::IpNetwork;
use num_traits::cast::FromPrimitive;
use ordered_float::OrderedFloat;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use time::{Duration, OffsetDateTime};

use crate::{Error, Result, TransportProto, ffi, types::TypeId};

/// Trait so we code can work with both `ffi::Val` and `ffi::ZVal`.
pub trait ValInterface {
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
        TypeTag::TYPE_DOUBLE => Self::Double(val.as_double().into()),
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
            Self::Addr(Addr::new(addr.try_into()?))
        }
        TypeTag::TYPE_SUBNET => {
            let sub = val.as_subnet_val().ok_or(Error::ValueUnset)?;
            let sub = ffi::Subnet::from(sub);
            let network = IpNetwork::new(sub.prefix.try_into()?, sub.width.try_into()?)?;
            Self::Subnet(Subnet::new(network))
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
            Self::Enum(TypeId::new(type_.GetName().to_string()), val.as_enum()?)
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

                let key: Result<Box<[Val]>> = cur.key().try_into();
                let key = key.map(|x| x.into_iter().map(Val::into_owned).collect());

                let val =  cur.value_ref().map_or(Ok(Val::None), TryInto::try_into);

                Some((key, val))
            }).map(|(k, v)| Ok((k?, v?)))
            .collect();

            if type_.IsSet() {
                let xs = xs?;
                let xs = xs.into_iter().map(|(k, _)| k).collect();
                Val::Set(xs)
            } else {
                Val::Table(xs?.into_iter().collect())
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

            Self::Record(TypeId::new(ty.GetName().to_string()), fields?)
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

/// Rust type modelling `zeek::Val`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum Val<'a> {
    None,
    Bool(bool),
    Count(u64),
    Int(i64),
    Double(OrderedFloat<f64>),
    Enum(TypeId<'a>, u64),
    String(Cow<'a, [u8]>),
    Port {
        num: u32,
        proto: TransportProto,
    },
    // Use custom type for special handling of mapped IPv6 addresses.
    Addr(Addr),
    // Use custom type since `IpNetwork` by default compares for bit equality, but
    // we want equivalence.
    Subnet(Subnet),
    Interval(Duration),
    Time(OffsetDateTime),
    Vec(Vec<Val<'a>>),
    List(Box<[Val<'a>]>),
    Set(BTreeSet<Box<[Val<'a>]>>),
    // Serialize tables as vectors since formats like JSON do not support multiple keys.
    Table(
        // #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
        #[cfg_attr(
            feature = "serde",
            serde(with = "serde_with::As::<Vec<(serde_with::Same, serde_with::Same)>>")
        )]
        BTreeMap<Box<[Val<'a>]>, Val<'a>>,
    ),
    Pattern {
        exact: Cow<'a, str>,
        anywhere: Cow<'a, str>,
    },
    Record(TypeId<'a>, BTreeMap<Cow<'a, str>, Val<'a>>),
}

impl Val<'_> {
    /// Convert the value into a Zeek value pointer.
    ///
    /// Passing `None` for `ty` implies `any` target type.
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion of the value or any of its parts fail.
    #[allow(clippy::too_many_lines)]
    pub fn to_valptr(self, ty_orig: Option<&ffi::TypePtr>) -> Result<UniquePtr<ffi::ValPtr>> {
        // We need special treatment for deserializing to an `any` since we might not have enough
        // type information (e.g., for empty containers)
        //
        // TODO(bbannier): Ideally we wouldn't need to look at the dest type `ty` here at all, but
        // unfortunately Zeek requires more typing than we would like.
        //
        // TODO(bbannier): Revisit this once treatment of empty containers improves in Zeek, see
        // https://github.com/zeek/zeek/issues/5114 and https://github.com/zeek/zeek/issues/5115.
        //
        // Map `TYPE_ANY` to `None`.
        let ty = ty_orig.and_then(|t| {
            t.val()
                .filter(|ty| !matches!(ty.Tag(), zeek::TypeTag::TYPE_ANY))
        });

        /// Helper macro to validate that the type tag matches what is expected for deserializing the current `Val`.
        macro_rules! check_dest_type {
            ($expected:expr) => {
                ty.map(crate::ffi::Type::Tag)
                    .map(|tag| {
                        use crate::ffi::TypeTag;
                        if tag == $expected {
                            Ok(())
                        } else {
                            Err(Error::UnexpectedDestType {
                                expected: $expected,
                                actual: tag,
                            })
                        }
                    })
                    .unwrap_or_else(|| Ok(()))?;
            };
        }

        Ok(match self {
            Val::None => ffi::make_null(),
            Val::Bool(x) => {
                check_dest_type!(TypeTag::TYPE_BOOL);
                ffi::make_bool(x)
            }
            Val::Count(x) => {
                check_dest_type!(TypeTag::TYPE_COUNT);
                ffi::make_count(x)
            }
            Val::Int(x) => {
                check_dest_type!(TypeTag::TYPE_INT);
                ffi::make_int(x)
            }
            Val::Double(x) => {
                check_dest_type!(TypeTag::TYPE_DOUBLE);
                ffi::make_double(*x)
            }
            Val::String(x) => {
                check_dest_type!(TypeTag::TYPE_STRING);
                ffi::make_string(&x)
            }
            Val::Pattern { exact, anywhere } => {
                check_dest_type!(TypeTag::TYPE_PATTERN);
                ffi::make_pattern(&exact, &anywhere)
            }
            Val::Interval(x) => {
                check_dest_type!(TypeTag::TYPE_INTERVAL);
                ffi::make_interval(x.as_seconds_f64())
            }
            Val::Time(x) => {
                check_dest_type!(TypeTag::TYPE_TIME);

                let offset_ns = x.unix_timestamp_nanos();
                let offset_ns = f64::from_i128(offset_ns)
                    .ok_or(Error::UnrepresentableTimeOffsetNanos(offset_ns))?;
                let secs = offset_ns / 1e9;
                ffi::make_time(secs)
            }
            Val::Addr(x) => {
                check_dest_type!(TypeTag::TYPE_ADDR);
                ffi::make_addr(&x.to_string())
            }
            Val::Subnet(x) => {
                check_dest_type!(TypeTag::TYPE_SUBNET);
                ffi::make_subnet(&x.network().to_string(), x.prefix())
            }
            Val::Port { num, proto } => {
                check_dest_type!(TypeTag::TYPE_PORT);
                ffi::make_port(num, proto.into())
            }
            Val::Enum(id, x) => {
                check_dest_type!(TypeTag::TYPE_ENUM);

                let ty = zeek::id::find_type(id.name())
                    .val()
                    .ok_or(Error::UnknownType(id.name().into()))?;

                let ty = ty
                    .as_enum_type()
                    .ok_or_else(|| Error::UnexpectedTypeDefinition {
                        type_: id.name().into(),
                        expected: ffi::TypeTag::TYPE_ENUM,
                        actual: ty.Tag(),
                    })?;
                ffi::make_enum(x, ty)
            }
            Val::Record(id, fields) => {
                check_dest_type!(TypeTag::TYPE_RECORD);

                let ty = zeek::id::find_type(id.name())
                    .val()
                    .ok_or(Error::UnknownType(id.name().into()))?;
                let ty = ty
                    .as_record_type()
                    .ok_or_else(|| Error::UnexpectedTypeDefinition {
                        type_: id.name().into(),
                        expected: ffi::TypeTag::TYPE_RECORD,
                        actual: ty.Tag(),
                    })?;

                let (names, data): (Vec<_>, Vec<_>) = fields
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let ty = ty.get_field_type(&k)?;
                        let v = v.to_valptr(Some(ty));

                        Some((k, v))
                    })
                    .unzip();

                let mut result = ffi::ValPtrVector::make(data.len());

                for x in data {
                    result.pin_mut().push(x?);
                }

                let names: Vec<_> = names.iter().map(AsRef::as_ref).collect();
                ffi::make_record(
                    &names,
                    result,
                    ty_orig.ok_or(Error::InsufficientTypeInformation)?,
                )?
            }
            Val::Vec(xs) => {
                check_dest_type!(TypeTag::TYPE_VECTOR);

                let yield_ = zeek::base_type(zeek::TypeTag::TYPE_ANY);

                let mut vals = ffi::ValPtrVector::make(xs.len());

                for x in xs {
                    vals.pin_mut().push(x.to_valptr(Some(yield_))?);
                }

                ffi::make_vector(vals, ty_orig.ok_or(Error::InsufficientTypeInformation)?)
            }
            Val::List(xs) => {
                // Cannot check the dest type here since Zeek has no concept of a "ListType".
                // Instead lists are encoded with a `TypeTag == TYPE_LIST`, but with a type of the
                // list elements.

                if xs.iter().any(|x| matches!(x, Val::None)) {
                    Err(Error::ValueUnset)?;
                }

                let mut vals = ffi::ValPtrVector::make(xs.len());

                for x in xs {
                    vals.pin_mut().push(x.to_valptr(ty_orig)?);
                }

                ffi::make_list(vals)
            }
            Val::Set(xs) => {
                check_dest_type!(TypeTag::TYPE_TABLE);

                // Cannot encode to `any` target type.
                let ty_ = ty.ok_or(Error::InsufficientTypeInformation)?;
                let ty_orig = ty_orig.ok_or(Error::InsufficientTypeInformation)?;

                let tt = if ty_.Tag() == zeek::TypeTag::TYPE_TABLE {
                    ty_.as_table_type()
                } else {
                    None
                }
                .ok_or(Error::ValueUnset)?;

                let key_type = tt.GetIndexTypes();

                let mut keys = ffi::ValPtrVector::make(xs.len());

                let mut num_keys = None;
                for ks in xs {
                    if key_type.len() != ks.len() {
                        return Err(Error::InconsistentTableIndex {
                            expected: key_type.len(),
                            actual: ks.len(),
                        });
                    }

                    if let Some(num_keys) = num_keys
                        && num_keys != ks.len()
                    {
                        return Err(Error::InconsistentTableIndex {
                            expected: num_keys,
                            actual: ks.len(),
                        });
                    }

                    num_keys = Some(ks.len());

                    let mut ks_ = ffi::ValPtrVector::make(ks.len());
                    for (k, ty) in ks.into_iter().zip(key_type) {
                        ks_.pin_mut().push(k.to_valptr(Some(ty))?);
                    }

                    keys.pin_mut().push(ffi::make_list(ks_));
                }

                ffi::make_set(keys, ty_orig)
            }
            Val::Table(xs) => {
                check_dest_type!(TypeTag::TYPE_TABLE);

                // Cannot encode to `any` target type.
                let ty = ty.ok_or(Error::InsufficientTypeInformation)?;
                let ty = if ty.Tag() == ffi::TypeTag::TYPE_TABLE {
                    ty.as_table_type()
                } else {
                    None
                }
                .ok_or(Error::ValueUnset)?;

                let mut keys = ffi::ValPtrVector::make(xs.len());
                let mut values = ffi::ValPtrVector::make(xs.len());

                let yield_type = ty.Yield();
                let index_types = ty.GetIndexTypes();

                for (ks, v) in xs {
                    if ks.len() != index_types.len() {
                        Err(Error::InconsistentTableIndex {
                            expected: index_types.len(),
                            actual: ks.len(),
                        })?;
                    }

                    let mut ks_ = ffi::ValPtrVector::make(ks.len());
                    for (k, ty) in ks.into_iter().zip(index_types) {
                        ks_.pin_mut().push(k.to_valptr(Some(ty))?);
                    }

                    keys.pin_mut().push(ffi::make_list(ks_));
                    values.pin_mut().push(v.to_valptr(Some(yield_type))?);
                }

                ffi::make_table(
                    keys,
                    values,
                    ty_orig.ok_or(Error::InsufficientTypeInformation)?,
                )
            }
        })
    }

    /// Convert this `Val` into an owned version.
    pub fn into_owned(self) -> Val<'static> {
        match self {
            Val::String(x) => Val::String(Cow::from(x.into_owned())),
            Val::Vec(x) => Val::Vec(x.into_iter().map(Val::into_owned).collect()),
            Val::List(x) => Val::List(x.into_iter().map(Val::into_owned).collect()),
            Val::Set(x) => {
                let x = x
                    .into_iter()
                    .map(|k| k.into_iter().map(Val::into_owned).collect())
                    .collect();
                Val::Set(x)
            }
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
            Val::Record(id, x) => {
                let id = id.into_owned();
                let x = x
                    .into_iter()
                    .map(|(k, v)| (Cow::from(k.into_owned()), v.into_owned()));

                Val::Record(id, x.collect())
            }
            Val::Enum(id, x) => Val::Enum(id.into_owned(), x),

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

impl<'a> TryFrom<&'a ffi::ListVal> for Box<[Val<'a>]> {
    type Error = Error;

    fn try_from(value: &'a ffi::ListVal) -> Result<Self> {
        let len = usize::try_from(value.Length())?;
        (0..len)
            .map(|i| {
                value
                    .Idx(i)
                    .val()
                    .map_or_else(|| Ok(Val::None), TryInto::try_into)
            })
            .collect()
    }
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

/// An [`IpAddr`] with Zeek semantics.
///
/// Zeek implicitly converts IPv6-mapped IPv4 addresses to IPv4. This type does this automatically.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Addr(IpAddr);

impl Addr {
    #[must_use]
    pub fn new(addr: IpAddr) -> Self {
        let addr = match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(..) => v4,
        };

        Self(addr)
    }

    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.0
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An `IpNetwork` with Zeek semantics.
///
/// In contrast to `IpNetwork` Zeek's subnet implicitly truncates to the network part of the
/// address. Zeek also converts IPv6-mapped IPv4 addresses in the network part to IPv4. This type
/// does this automatically.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Subnet(IpNetwork);

impl Subnet {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn new(network: IpNetwork) -> Self {
        let addr = Addr::new(network.network());
        Self(IpNetwork::new(addr.addr(), network.prefix()).expect("network should be valid"))
    }

    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.0.network()
    }

    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.0.prefix()
    }
}

#[cfg(feature = "proptest")]
mod proptest_tools {
    use crate::types::{SetType, TableType};
    use crate::val::{Addr, Subnet};
    use crate::{TransportProto, Val, types::Type};
    use ipnetwork::IpNetwork;
    use ipnetwork::{Ipv4Network, Ipv6Network};
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use time::{Duration, OffsetDateTime};

    /// Adaptor to generate arbitrary [`Val`]s of a given [`Type`].
    #[allow(clippy::too_many_lines)]
    pub fn arbitrary_val(ty: crate::types::Type<'static>) -> BoxedStrategy<Val<'static>> {
        match ty {
            Type::Bool => any::<bool>().prop_map(Val::Bool).boxed(),
            Type::Count => any::<u64>().prop_map(Val::Count).boxed(),
            Type::Int => any::<i64>().prop_map(Val::Int).boxed(),
            Type::Double => {
                // Only generate powers of 2 so we have a higher change of values roundtripping.
                (-1022..=1023i32)
                    .prop_map(|exp| Val::Double(2.0_f64.powi(exp).into()))
                    .boxed()
            }
            Type::String => prop::collection::vec(any::<u8>(), 0..16)
                .prop_map(|x| Val::String(x.into()))
                .boxed(),
            Type::Port => (any::<u16>(), any::<TransportProto>())
                .prop_map(|(num, proto)| Val::Port {
                    num: num.into(),
                    proto,
                })
                .boxed(),
            Type::Addr => any::<IpAddr>()
                .prop_map(|x| Val::Addr(Addr::new(x)))
                .boxed(),
            Type::Subnet => prop_oneof![
                (any::<Ipv4Addr>(), 0..=32u8)
                    .prop_filter_map("invalid ipv4 address", |(addr, prefix)| Some(Val::Subnet(
                        Subnet::new(IpNetwork::V4(Ipv4Network::new(addr, prefix).ok()?))
                    )))
                    .boxed(),
                (any::<Ipv6Addr>(), 0..=32u8).prop_filter_map(
                    "invalid ipv6 address",
                    |(addr, prefix)| Some(Val::Subnet(Subnet::new(IpNetwork::V6(
                        Ipv6Network::new(addr, prefix).ok()?
                    ))))
                )
            ]
            .boxed(),

            Type::Interval => (-1_000_000..=1_000_000i64, any::<i32>())
                .prop_map(|(s, ns)| {
                    // Limit seconds range since Zeek interval loose precision near the edges of range.
                    Val::Interval(Duration::new(s, ns))
                })
                .boxed(),
            Type::Time => {
                (-1_000..1_000_000_000i64)
                    .prop_filter_map("invalid timestamp", |x| {
                        // Limit time range since Zeek time looses precision near edges of range.
                        Some(Val::Time(OffsetDateTime::from_unix_timestamp(x).ok()?))
                    })
                    .boxed()
            }
            // TODO(bbannier): Enforce non-zero size on type system.
            Type::Pattern => prop::collection::vec("[a-zA-Z]", 1..32)
                .prop_map(|v| v.into_iter().collect::<String>())
                .prop_map(|pat| Val::Pattern {
                    // We use the same pattern here to keep things consistent.
                    // TODO(bbannier): Constrain this on the API level.
                    exact: pat.clone().into(),
                    anywhere: pat.into(),
                })
                .boxed(),
            Type::Vec(xs) => {
                let num_elements = 0..10;
                prop::collection::vec(
                    prop_oneof![
                        arbitrary_val(*xs),
                        Just(Val::None), // Holes.
                    ],
                    num_elements,
                )
                .prop_map(Val::Vec)
                .boxed()
            }
            Type::List(xs) => {
                let num_elements = 0..10;
                match xs {
                    // list of any.
                    None => {
                        let any_val = any::<Type>()
                            .prop_flat_map(arbitrary_val)
                            .prop_filter("lists have no holes", |x| !matches!(x, Val::None));
                        prop::collection::vec(any_val, num_elements)
                            .prop_map(Vec::into_boxed_slice)
                            .prop_map(Val::List)
                            .boxed()
                    }
                    Some(ty) => prop::collection::vec(arbitrary_val(*ty), num_elements)
                        .prop_map(Vec::into_boxed_slice)
                        .prop_map(Val::List)
                        .boxed(),
                }
            }
            Type::Set(SetType(tys)) => {
                let elems = tys
                    .into_iter()
                    .map(arbitrary_val)
                    .collect::<Vec<_>>()
                    .prop_map(Vec::into_boxed_slice);
                prop::collection::btree_set(elems, 1..4)
                    .prop_map(Val::Set)
                    .boxed()
            }
            Type::Table(TableType(key, value)) => {
                let key = key
                    .into_iter()
                    .map(arbitrary_val)
                    .collect::<Vec<_>>()
                    .prop_map(Vec::into_boxed_slice);

                let value = value.map_or(Just(Val::None).boxed(), |v| arbitrary_val(*v));

                prop::collection::btree_map(key, value, 1..4)
                    .prop_map(Val::Table)
                    .boxed()
            }
            Type::Enum(id) => {
                let id = id.into_owned();
                (0..4u64)
                    .prop_map(move |n| Val::Enum(id.clone(), n))
                    .boxed()
            }
            Type::Record(..) => {
                // Generating records from the type requires looking up field
                // definitions which is very expensive. Skip them here.
                todo!()
            }
        }
        .boxed()
    }

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
}

#[cfg(feature = "proptest")]
pub use proptest_tools::arbitrary_val;

macro_rules! impl_val_from {
    ($variant:path, $ty:ty, $a:lifetime) => {
        impl<$a> From<$ty> for Val<$a> {
            fn from(value: $ty) -> Self {
                $variant(value.into())
            }
        }
    };
}

macro_rules! impl_val_try_into {
    ($variant:path, $ty:ty, $a:lifetime) => {
        impl<$a> TryInto<$ty> for Val<$a> {
            type Error = Error;

            fn try_into(self) -> std::result::Result<$ty, Self::Error> {
                let $variant(x) = self else {
                    Err(Error::ValueUnset)?
                };
                let x = x.try_into()?;
                Ok(x)
            }
        }
    };
}

macro_rules! impl_val_conversions {
    ($variant:path, $ty:ty, $a:lifetime) => {
        impl_val_from!($variant, $ty, $a);
        impl_val_try_into!($variant, $ty, $a);
    };
}

impl From<()> for Val<'_> {
    fn from((): ()) -> Self {
        Val::None
    }
}

impl TryInto<()> for Val<'_> {
    type Error = Error;

    fn try_into(self) -> std::result::Result<(), Self::Error> {
        if matches!(self, Val::None) {
            Ok(())
        } else {
            Err(Error::ValueUnset)
        }
    }
}

impl_val_conversions!(Val::Bool, bool, 'a);

impl_val_conversions!(Val::Count, u8, 'a);
impl_val_conversions!(Val::Count, u16, 'a);
impl_val_conversions!(Val::Count, u32, 'a);
impl_val_conversions!(Val::Count, u64, 'a);

impl_val_conversions!(Val::Int, i8,'a);
impl_val_conversions!(Val::Int, i16,'a);
impl_val_conversions!(Val::Int, i32,'a);
impl_val_conversions!(Val::Int, i64,'a);

impl_val_conversions!(Val::Double, f64,'a);
impl_val_conversions!(Val::Double, OrderedFloat<f64>, 'a);

impl_val_conversions!(Val::String, Cow<'a, [u8]>, 'a);

impl_val_conversions!(Val::Addr, Addr, 'a);
impl_val_conversions!(Val::Subnet, Subnet, 'a);
impl_val_conversions!(Val::Interval, Duration, 'a);
impl_val_conversions!(Val::Time, OffsetDateTime,'a);
impl_val_conversions!(Val::Vec, Vec<Val<'a>>, 'a);
impl_val_conversions!(Val::Set, BTreeSet<Box<[Val<'a>]>>, 'a);
impl_val_conversions!(Val::Table, BTreeMap<Box<[Val<'a>]>, Val<'a>>, 'a);
