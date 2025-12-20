use std::{fmt::Debug, pin::Pin};

use cxx::UniquePtr;
use thiserror::Error;
use zeek_types::{ByteBufferWriter, support::ByteBuffer, zeek};

use crate::{
    ffi::Format,
    serialize::{Deserialize, Serialize},
};

mod serialize;
mod zeek_websocket_v1;

#[cxx::bridge]
mod ffi {
    #[derive(Debug)]
    enum Format {
        Binary = 0,
        Human = 1,
    }

    extern "Rust" {
        fn serialize_val(value: &Val, format: Format, buf: Pin<&mut ByteBuffer>) -> Result<()>;
        fn deserialize_val(buf: &[u8], format: Format, ty: &TypePtr) -> Result<UniquePtr<ValPtr>>;

        fn serialize_event(event: &Event, format: Format, buf: Pin<&mut ByteBuffer>) -> Result<()>;
        fn deserialize_event(buf: &[u8], format: Format) -> Result<UniquePtr<Event>>;

        fn format_name(f: Format) -> String;
    }

    #[namespace = "::zeek"]
    unsafe extern "C++" {
        type EnumValPtr = zeek_types::zeek::EnumValPtr;
        type TypePtr = zeek_types::zeek::TypePtr;
        type Val = zeek_types::zeek::Val;
        type ValPtr = zeek_types::zeek::ValPtr;

        #[namespace = "::zeek::cluster"]
        type Event = zeek_types::zeek::cluster::Event;
    }

    #[namespace = "::support"]
    unsafe extern "C++" {
        include!("zeek-types/src/interop.h");

        type ByteBuffer = zeek_types::support::ByteBuffer;
        type ValPtrVector = zeek_types::support::ValPtrVector;
    }
}

type Result<T> = std::result::Result<T, Error>;

fn serialize_val(value: &zeek::Val, format: ffi::Format, buf: Pin<&mut ByteBuffer>) -> Result<()> {
    let buf = ByteBufferWriter::new(buf);
    value.serialize(format, buf)
}

fn deserialize_val(
    buf: &[u8],
    format: Format,
    ty: &zeek::TypePtr,
) -> Result<UniquePtr<zeek::ValPtr>> {
    let value = UniquePtr::<zeek::ValPtr>::deserialize(buf, format, Some(ty))?;
    Ok(value)
}

fn serialize_event(
    event: &zeek::cluster::Event,
    format: Format,
    buf: Pin<&mut ByteBuffer>,
) -> Result<()> {
    let buf = ByteBufferWriter::new(buf);
    event.serialize(format, buf)
}

fn deserialize_event(buf: &[u8], format: Format) -> Result<UniquePtr<zeek::cluster::Event>> {
    let event = UniquePtr::<zeek::cluster::Event>::deserialize(buf, format, None)?;
    Ok(event)
}

#[derive(Error, Debug)]
enum Error {
    #[error(transparent)]
    Conversion(#[from] zeek_types::Error),

    #[error(transparent)]
    Encode(#[from] bincode::error::EncodeError),

    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("deserialization left {0} bytes unconsumed")]
    UnconsumedBytes(usize),

    #[error("unsupported format {0:?}")]
    UnsupportedFormat(ffi::Format),

    #[error("{0}")]
    CxxException(#[from] cxx::Exception),
}

fn format_name(f: Format) -> String {
    format!("{f:?}")
}
