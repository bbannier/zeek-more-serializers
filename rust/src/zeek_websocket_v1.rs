use std::{borrow::Cow, ffi::CStr, num::TryFromIntError, str::Utf8Error, string::FromUtf8Error};
use thiserror::Error;

use cxx::let_cxx_string;
use zeek_types::{
    TransportProto, TypeId, Val,
    zeek::{self, id::find_type},
};
use zeek_websocket_types::{IpNetwork, Port, Protocol, TableEntry, Value};

struct WebSocketValue(Value);

impl From<Value> for WebSocketValue {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

impl TryFrom<Val<'_>> for WebSocketValue {
    type Error = Error;

    #[allow(clippy::too_many_lines)]
    fn try_from(value: Val) -> Result<Self, Self::Error> {
        Ok(WebSocketValue(match value {
            Val::None => Value::None,
            Val::Bool(x) => Value::Boolean(x),
            Val::Count(x) => Value::Count(x),
            Val::Int(x) => Value::Integer(x),
            Val::Double(x) => Value::Real(x),
            Val::String(x) => {
                // Preserve unicode characters, else unicode-escape `\u....`.
                let x = x.iter().map(|c| char::from(*c)).collect();
                Value::String(x)
            }
            Val::Port { num, proto } => {
                let protocol = match proto {
                    TransportProto::Unknown => Protocol::UNKNOWN,
                    TransportProto::Tcp => Protocol::TCP,
                    TransportProto::Udp => Protocol::UDP,
                    TransportProto::Icmp => Protocol::ICMP,
                };

                Value::Port(Port::new(num.try_into()?, protocol))
            }
            Val::Enum(id, val) => {
                let type_ = zeek::id::find_type(id.name())
                    .val()
                    .ok_or(Error::ValueUnset)?
                    .as_enum_type()
                    .ok_or(Error::ValueUnset)?;

                let enum_ = type_.Lookup(val.try_into()?);
                let enum_ = unsafe { CStr::from_ptr(enum_) }.to_str()?;

                let name = type_.GetName();

                Value::EnumValue(format!("{enum_}::{name}"))
            }
            Val::Addr(addr) => Value::Address(addr),
            Val::Subnet { prefix, width } => {
                Value::Subnet(IpNetwork::new(prefix, width.try_into()?)?)
            }
            Val::Interval(x) => Value::Timespan(x),
            Val::Time(x) => Value::Timestamp(x),
            Val::Vec(xs) => {
                let xs: Result<Vec<WebSocketValue>, _> =
                    xs.into_iter().map(TryInto::try_into).collect();
                let xs = xs?.into_iter().map(|x| x.0).collect();
                Value::Vector(xs)
            }
            Val::Set(xs) => {
                let xs: Result<_, Error> = xs
                    .into_iter()
                    .map(|x| {
                        let x: Result<_, _> = x
                            .into_iter()
                            .map(|x| WebSocketValue::try_from(x).map(|x| x.0))
                            .collect();
                        Ok(Value::Vector(x?))
                    })
                    .collect();
                Value::Set(xs?)
            }
            Val::Table(xs) => {
                let xs: Result<_, Error> = xs
                    .into_iter()
                    .map(|(k, v)| {
                        let k: Result<_, _> = k
                            .into_iter()
                            .map(|x| WebSocketValue::try_from(x).map(|x| x.0))
                            .collect();
                        let k = Value::Vector(k?);
                        let v: WebSocketValue = v.try_into()?;
                        Ok(TableEntry::new(k, v.0))
                    })
                    .collect();

                Value::Table(xs?)
            }
            Val::Record(id, mut xs) => {
                let ty = find_type(id.name())
                    .val()
                    .ok_or(Error::ValueUnset)?
                    .as_record_type()
                    .ok_or(Error::ValueUnset)?;

                let mut values = Vec::new();
                for i in 0..ty.NumFields() {
                    let Some(Ok(name)) = ty.field_name(i) else {
                        continue;
                    };
                    let value = xs
                        .remove(name)
                        .map_or(Ok(WebSocketValue(Value::None)), TryInto::try_into)?
                        .0;
                    values.push(value);
                }
                Value::Vector(values)
            }
            Val::List(..) | Val::Pattern { .. } => Err(Error::UnsupportedType)?,
        }))
    }
}

impl TryFrom<WebSocketValue> for Val<'static> {
    type Error = Error;

    fn try_from(value: WebSocketValue) -> Result<Self, Self::Error> {
        Ok(match value.0 {
            Value::None => Val::None,
            Value::Boolean(x) => Val::Bool(x),
            Value::Count(x) => Val::Count(x),
            Value::Integer(x) => Val::Int(x),
            Value::Real(x) => Val::Double(x),
            Value::String(x) => {
                let x: Cow<_> = x.as_bytes().into();
                Val::String(Cow::from(x.into_owned()))
            }
            Value::Port(x) => {
                let num = x.number().into();
                let proto = match x.protocol() {
                    Protocol::TCP => TransportProto::Tcp,
                    Protocol::UDP => TransportProto::Udp,
                    Protocol::ICMP => TransportProto::Icmp,
                    Protocol::UNKNOWN => TransportProto::Unknown,
                };
                Val::Port { num, proto }
            }
            Value::EnumValue(x) => {
                let (enum_name, value) = x.rsplit_once("::").ok_or(Error::ValueUnset)?;
                let ty = find_type(enum_name)
                    .val()
                    .ok_or(Error::ValueUnset)?
                    .as_enum_type()
                    .ok_or(Error::ValueUnset)?;

                let_cxx_string!(name = value);
                let value = ty.LookupName(&name);
                let value = value.try_into()?;

                let id = TypeId::new(enum_name).into_owned();
                Val::Enum(id, value)
            }
            Value::Address(x) => Val::Addr(x),
            Value::Subnet(x) => Val::Subnet {
                prefix: x.network(),
                width: x.prefix().into(),
            },
            Value::Timespan(x) => Val::Interval(x),
            Value::Timestamp(x) => Val::Time(x),
            Value::Vector(x) => {
                let x: Result<_, _> = x
                    .into_iter()
                    .map(WebSocketValue)
                    .map(TryInto::try_into)
                    .collect();
                Val::Vec(x?)
            }
            Value::Set(x) => {
                let x: Result<_, _> = x
                    .into_iter()
                    .map(|x| {
                        let Value::Vector(x) = x else {
                            Err(Error::InconsistentValue)?
                        };
                        let x: Result<_, _> = x
                            .into_iter()
                            .map(WebSocketValue)
                            .map(TryInto::try_into)
                            .collect();
                        x
                    })
                    .collect();

                Val::Set(x?)
            }
            Value::Table(x) => {
                let x: Result<_, Error> = x
                    .into_iter()
                    .map(|x| {
                        let Value::Vector(k) = x.key else {
                            Err(Error::InconsistentValue)?
                        };
                        let k: Result<_, _> = k
                            .into_iter()
                            .map(WebSocketValue)
                            .map(TryInto::try_into)
                            .collect();

                        Ok((k?, WebSocketValue(x.value).try_into()?))
                    })
                    .collect();

                Val::Table(x?)
            }
        })
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("type is unsupported")]
    UnsupportedType,

    #[error("internals of value are inconsistent")]
    InconsistentValue,

    #[error("value out of range")]
    ValueOutOfRange(#[from] TryFromIntError),

    #[error("value is not set, but should not be")]
    ValueUnset,

    #[error("invalid subnet")]
    InvalidSubnet(#[from] ipnetwork::IpNetworkError),

    #[error("string is not valid UTF-8")]
    InvalidUtf8String(#[from] Utf8Error),

    #[error("bytes are not valid UTF-8")]
    InvalidUtf8Bytes(#[from] FromUtf8Error),
}
