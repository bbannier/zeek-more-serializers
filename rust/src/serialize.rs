use std::io::{BufWriter, Write};

use postcard::ser_flavors::{self};
use zeek_types::zeek;

use crate::{Error, Result, ffi::Format};

pub(crate) struct Binary;
pub(crate) struct Human;

pub(crate) trait ToSchema<'a, F> {
    type Schema: serde::Serialize;
    fn to_schema(&'a self) -> Result<Self::Schema>;
}

pub(crate) trait FromSchema<'de, F> {
    type Schema: serde::Deserialize<'de>;
    fn from_schema(schema: Self::Schema, typ: Option<&zeek::TypePtr>) -> Result<Self>
    where
        Self: Sized;
}

trait SerializerEngine {
    fn serialize<T, B>(val: &T, buf: B) -> Result<()>
    where
        T: serde::Serialize,
        B: Write;

    fn deserialize<'de, T: serde::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T>;
}

impl SerializerEngine for Binary {
    fn serialize<T, B>(val: &T, buf: B) -> Result<()>
    where
        T: serde::Serialize,
        B: Write,
    {
        let w = ser_flavors::io::WriteFlavor::new(buf);
        postcard::serialize_with_flavor(val, w)?;
        Ok(())
    }

    fn deserialize<'de, T: serde::Deserialize<'de>>(buf: &'de [u8]) -> Result<T> {
        let value = postcard::from_bytes(buf)?;
        Ok(value)
    }
}

impl SerializerEngine for Human {
    fn serialize<T, B>(val: &T, buf: B) -> Result<()>
    where
        T: serde::Serialize,
        B: Write,
    {
        serde_json::to_writer(buf, val)?;
        Ok(())
    }

    fn deserialize<'de, T: serde::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T> {
        let value = serde_json::from_slice(bytes)?;
        Ok(value)
    }
}

fn serialize<F, T, B>(value: &T, buf: B) -> Result<()>
where
    F: SerializerEngine,
    T: for<'a> ToSchema<'a, F> + ?Sized,
    B: Write,
{
    let buf = BufWriter::new(buf);
    let schema = value.to_schema()?;
    F::serialize(&schema, buf)
}

pub(crate) trait Serialize:
    for<'a> ToSchema<'a, Binary> + for<'a> ToSchema<'a, Human>
{
    fn serialize<B>(&self, format: Format, buf: B) -> Result<()>
    where
        B: Write,
    {
        match format {
            Format::Binary => serialize::<Binary, Self, _>(self, buf),
            Format::Human => serialize::<Human, Self, _>(self, buf),
            _ => Err(Error::UnsupportedFormat(format))?,
        }
    }
}

impl<T> Serialize for T where T: for<'a> ToSchema<'a, Binary> + for<'a> ToSchema<'a, Human> {}

pub(crate) trait Deserialize:
    for<'de> FromSchema<'de, Binary> + for<'de> FromSchema<'de, Human>
{
    fn deserialize(bytes: &[u8], format: Format, typ: Option<&zeek::TypePtr>) -> Result<Self>
    where
        Self: Sized,
    {
        match format {
            Format::Binary => {
                let schema = Binary::deserialize::<<Self as FromSchema<Binary>>::Schema>(bytes)?;
                Ok(<Self as FromSchema<Binary>>::from_schema(schema, typ)?)
            }
            Format::Human => {
                let schema = Human::deserialize::<<Self as FromSchema<Human>>::Schema>(bytes)?;
                Ok(<Self as FromSchema<Human>>::from_schema(schema, typ)?)
            }
            _ => Err(Error::UnsupportedFormat(format)),
        }
    }
}

impl<T> Deserialize for T
where
    T: for<'de> FromSchema<'de, Binary>,
    T: for<'de> FromSchema<'de, Human>,
{
}

//////////////////////////////////////////

impl<'a> ToSchema<'a, Binary> for zeek::Val {
    type Schema = zeek_types::Val<'a>;
    fn to_schema(&'a self) -> Result<Self::Schema> {
        let schema = self.try_into()?;
        Ok(schema)
    }
}

impl<'a> ToSchema<'a, Binary> for zeek::cluster::Event {
    type Schema = zeek_types::Event<'a>;
    fn to_schema(&'a self) -> Result<Self::Schema> {
        let schema = self.try_into()?;
        Ok(schema)
    }
}

impl<'a> ToSchema<'a, Human> for zeek::Val {
    type Schema = zeek_types::Val<'a>;
    fn to_schema(&'a self) -> Result<Self::Schema> {
        ToSchema::<Binary>::to_schema(self)
    }
}

impl<'a> ToSchema<'a, Human> for zeek::cluster::Event {
    type Schema = zeek_types::Event<'a>;
    fn to_schema(&'a self) -> Result<Self::Schema> {
        ToSchema::<Binary>::to_schema(self)
    }
}

impl<'de> FromSchema<'de, Binary> for cxx::UniquePtr<zeek::ValPtr> {
    type Schema = zeek_types::Val<'de>;
    fn from_schema(schema: Self::Schema, typ: Option<&zeek::TypePtr>) -> Result<Self> {
        let val = schema.to_valptr(typ)?;
        Ok(val)
    }
}

impl<'de> FromSchema<'de, Binary> for cxx::UniquePtr<zeek::cluster::Event> {
    type Schema = zeek_types::Event<'de>;
    fn from_schema(schema: Self::Schema, _typ: Option<&zeek::TypePtr>) -> Result<Self>
    where
        Self: Sized,
    {
        // We do not look at the target type at all, and instead derive this from the parsed event type.
        let event = schema.try_into()?;
        Ok(event)
    }
}

impl<'de> FromSchema<'de, Human> for cxx::UniquePtr<zeek::ValPtr> {
    type Schema = zeek_types::Val<'de>;
    fn from_schema(schema: Self::Schema, typ: Option<&zeek::TypePtr>) -> Result<Self>
    where
        Self: Sized,
    {
        // We do not look at the target type at all, and instead derive this from the parsed event type.
        FromSchema::<Binary>::from_schema(schema, typ)
    }
}

impl<'de> FromSchema<'de, Human> for cxx::UniquePtr<zeek::cluster::Event> {
    type Schema = zeek_types::Event<'de>;
    fn from_schema(schema: Self::Schema, typ: Option<&zeek::TypePtr>) -> Result<Self>
    where
        Self: Sized,
    {
        FromSchema::<Binary>::from_schema(schema, typ)
    }
}
