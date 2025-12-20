use std::{num::TryFromIntError, str::Utf8Error};

use thiserror::Error;

use crate::ffi;

/// Possible errors.
#[derive(Error, Debug)]
pub enum Error {
    #[error("value tag and contents are inconsistent")]
    InconsistentTagValue,

    #[error("mismachting type tag: expected {expected:?}, got {actual:?}")]
    MismatchingType {
        expected: ffi::TypeTag,
        actual: ffi::TypeTag,
    },

    #[error("value should be set but is not")]
    ValueUnset,

    #[error("unsupported address size {0}")]
    UnsupportedAddrSize(u8),

    #[error("transport proto {0:?} is unknown")]
    UnknownTransportProto(ffi::TransportProto),

    #[error("type tag {0:?} is unknown")]
    UnknownTypeTag(ffi::TypeTag),

    #[error("type '{0}' is unknown")]
    UnknownType(String),

    #[error("type tag {0:?} is unsupported")]
    UnsupportedTypeTag(ffi::TypeTag),

    #[error("integer does not fit expected range: {0}")]
    IntegerConversion(#[from] TryFromIntError),

    #[error("invalid time value: {0}")]
    TimeConversion(#[from] time::error::ComponentRange),

    #[error("cannot represent second offset {0} as nanoseconds")]
    UnrepresentableTimeOffsetDouble(f64),

    #[error("cannot represent nanosecond offset {0} as seconds")]
    UnrepresentableTimeOffsetNanos(i128),

    #[error("inconsistent table index size: expected {expected}, got {actual}")]
    InconsistentTableIndex { expected: usize, actual: usize },

    #[error("insufficient type information to deserialize value")]
    InsufficientTypeInformation,

    #[error("found unexpected definition of type '{type_}: expected {expected:?}, got {actual:?}")]
    UnexpectedTypeDefinition {
        type_: String,
        expected: ffi::TypeTag,
        actual: ffi::TypeTag,
    },

    #[error("utf8 error: {0}")]
    Utf8Error(#[from] Utf8Error),

    #[error("could not determine type of argument {0} in event {1}")]
    UnknownEventArgType(usize, String),

    #[error("metadata ID {0} is unknown")]
    UnknownMetadataId(u64),

    #[error("{0}")]
    CxxException(#[from] cxx::Exception),
}
