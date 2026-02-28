//! Types for working with the Zeek C++ API.

#![allow(dead_code)]

mod error;
mod event;
pub mod types;
mod val;
mod zval;

#[cfg(feature = "proptest")]
pub use val::arbitrary_val;

use core::str;
use cxx::{CxxVector, UniquePtr};
use std::{
    ffi::{CStr, CString},
    io::Write,
    net::IpAddr,
    pin::Pin,
};

pub use crate::{
    error::Error,
    event::Event,
    val::{Addr, Subnet, Val},
    zval::TypedZVal,
};
pub use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

type Result<T> = std::result::Result<T, Error>;

/// Raw types exposed from Zeek's C++ API.
pub mod zeek {
    pub use crate::ffi::{
        AddrVal, Args, EnumType, EnumVal, EnumValPtr, EventMetadataDescriptor, ListVal, PatternVal,
        PortVal, RE_Matcher, RecordType, RecordVal, StringVal, SubNetVal, TableType, TableTypePtr,
        TableVal, Type, TypeList, TypeListPtr, TypePtr, TypeTag, Val, ValPtr, VectorType,
        VectorVal, ZVal, base_type,
    };

    pub mod cluster {
        pub use crate::ffi::Event;
    }

    pub mod detail {
        pub use crate::ffi::{Frame, MetadataEntry};
    }

    pub mod id {
        pub use crate::ffi::zeek_id_find_type as find_type;
    }
}

/// Helper types for working with C++ API types.
pub mod support {
    pub use crate::ByteBufferWriter;
    pub use crate::ffi::{
        ByteBuffer, PluginWrapper, TableEntry, TableIterator, TypePtrVector, TypedZVal,
        ValPtrVector, event_add_metadata, event_make, event_name,
        event_registry_lookup_event_arg_type, event_registry_lookup_metadata, val_manager_port,
        zeek_id_find_type,
    };
}

#[allow(
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::elidable_lifetime_names
)]
#[cxx::bridge]
mod ffi {
    // Make these enums usable across language boundaries. Consistency is checked by `cxx`.
    #[derive(Debug)]
    enum TypeTag {
        TYPE_VOID,
        TYPE_BOOL,
        TYPE_INT,
        TYPE_COUNT,
        TYPE_DOUBLE,
        TYPE_TIME,
        TYPE_INTERVAL,
        TYPE_STRING,
        TYPE_PATTERN,
        TYPE_ENUM,
        TYPE_PORT,
        TYPE_ADDR,
        TYPE_SUBNET,
        TYPE_ANY,
        TYPE_TABLE,
        TYPE_RECORD,
        TYPE_LIST,
        TYPE_FUNC,
        TYPE_FILE,
        TYPE_VECTOR,
        TYPE_OPAQUE,
        TYPE_TYPE,
        TYPE_ERROR,
    }

    #[derive(Debug)]
    enum TransportProto {
        TRANSPORT_UNKNOWN,
        TRANSPORT_TCP,
        TRANSPORT_UDP,
        TRANSPORT_ICMP,
    }

    struct Addr {
        len: u8,
        bytes: [u8; 16],
    }

    struct Subnet {
        prefix: Addr,
        width: isize,
    }

    /// Wrapper around a ZVal and its type.
    struct TypedZVal {
        val: *const ZVal,
        type_: *const Type,
    }

    #[namespace = "::zeek"]
    unsafe extern "C++" {
        include!("zeek/Type.h");
        type TypeTag;

        include!("interop.h");

        include!("zeek/Val.h");
        type Val;

        fn AsBool(self: &Val) -> bool;
        fn AsCount(self: &Val) -> u64;
        fn AsInt(self: &Val) -> i64;
        fn AsDouble(self: &Val) -> f64;
        fn AsStringVal(self: &Val) -> *const StringVal;
        fn AsInterval(self: &Val) -> f64;
        fn AsTime(self: &Val) -> f64;
        fn AsPortVal(self: &Val) -> *const PortVal;
        fn AsAddrVal(self: &Val) -> *const AddrVal;
        fn AsSubNetVal(self: &Val) -> *const SubNetVal;
        fn AsVectorVal(self: &Val) -> *const VectorVal;
        fn AsTableVal(self: &Val) -> *const TableVal;
        fn AsPatternVal(self: &Val) -> *const PatternVal;
        fn AsEnumVal(self: &Val) -> *const EnumVal;
        fn AsRecordVal(self: &Val) -> *const RecordVal;
        fn AsListVal(self: &Val) -> *const ListVal;
        fn GetType(self: &Val) -> &TypePtr;

        type AddrVal;
        type EnumVal;
        type EnumValPtr;
        type SubNetVal;
        type TableTypePtr;
        type TableVal;
        type TypeListPtr;
        type TypePtr;
        type ValPtr;

        fn get(self: &ValPtr) -> *mut Val;
        fn get(self: &TypeListPtr) -> *mut TypeList;
        fn get(self: &TypePtr) -> *mut Type;

        type EnumType;
        fn GetName(self: &EnumType) -> &CxxString;
        fn Lookup(self: &EnumType, value: i64) -> *const c_char;
        #[cxx_name = "Lookup"]
        fn LookupName(self: &EnumType, fullname: &CxxString) -> i64;

        type StringVal;
        fn Bytes(self: &StringVal) -> *const u8;
        fn Len(self: &StringVal) -> i32;

        type PortVal;
        fn Port(self: &PortVal) -> u32;
        fn PortType(self: &PortVal) -> TransportProto;

        type VectorVal;
        fn Size(self: &VectorVal) -> u32;

        type ListVal;
        fn Length(self: &ListVal) -> i32;
        fn Idx(self: &ListVal, i: usize) -> &ValPtr;

        type RecordType;
        unsafe fn GetFieldType(self: &RecordType, field_index: i32) -> &TypePtr;
        unsafe fn FieldOffset(self: &RecordType, field_name: *const c_char) -> i32;
        fn GetName(self: &RecordType) -> &CxxString;

        fn NumFields(self: &RecordType) -> i32;
        fn FieldName(self: &RecordType, i: i32) -> *const c_char;

        type VectorType;
        fn Yield(self: &VectorType) -> &TypePtr;

        type TypeList;
        fn GetTypes(self: &TypeList) -> &CxxVector<TypePtr>;

        type TableType;
        fn GetIndices(self: &TableType) -> &TypeListPtr;
        fn GetIndexTypes(self: &TableType) -> &CxxVector<TypePtr>;
        fn Yield(self: &TableType) -> &TypePtr;

        type PatternVal;
        fn AsPattern(self: &PatternVal) -> *const RE_Matcher;

        include!("zeek/RE.h");
        type RE_Matcher;
        fn PatternText(self: &RE_Matcher) -> *const c_char;
        fn AnywherePatternText(self: &RE_Matcher) -> *const c_char;

        type RecordVal;
        fn GetType(self: &RecordVal) -> &TypePtr;

        type Type;
        fn AsVectorType(self: &Type) -> *const VectorType;
        fn AsEnumType(self: &Type) -> *const EnumType;
        fn AsTypeList(self: &Type) -> *const TypeList;
        fn AsTableType(self: &Type) -> *const TableType;
        fn AsRecordType(self: &Type) -> *const RecordType;
        fn Tag(self: &Type) -> TypeTag;
        fn IsSet(self: &Type) -> bool;

        type Args;
        fn at(self: &Args, idx: usize) -> &ValPtr;
        fn size(self: &Args) -> usize;

        type EventMetadataDescriptor;
        fn IdVal(self: &EventMetadataDescriptor) -> &EnumValPtr;
        fn Type(self: &EventMetadataDescriptor) -> &TypePtr;

        include!("zeek/ZVal.h");
        type ZVal;
        fn AsInt(self: &ZVal) -> i64;
        fn AsCount(self: &ZVal) -> u64;
        fn AsDouble(self: &ZVal) -> f64;
        fn AsString(self: &ZVal) -> *mut StringVal;
        fn AsAddr(self: &ZVal) -> *mut AddrVal;
        fn AsSubNet(self: &ZVal) -> *mut SubNetVal;
        fn AsVector(self: &ZVal) -> *mut VectorVal;
        fn AsPattern(self: &ZVal) -> *mut PatternVal;
        fn AsTable(self: &ZVal) -> *mut TableVal;
        fn AsRecord(self: &ZVal) -> *mut RecordVal;
        fn AsList(self: &ZVal) -> *mut ListVal;
        fn AsAny(self: &ZVal) -> *mut Val;

        #[must_use]
        fn base_type(tag: TypeTag) -> &'static TypePtr;
    }

    #[namespace = "::zeek::cluster"]
    unsafe extern "C++" {
        include!("zeek/cluster/Event.h");
        type Event;
        fn Args(self: &Event) -> &Args;
        fn Metadata(self: &Event) -> *const CxxVector<MetadataEntry>;
    }

    #[namespace = "::zeek::detail"]
    unsafe extern "C++" {
        type MetadataEntry;
        fn Id(self: &MetadataEntry) -> u64;
        fn Val(self: &MetadataEntry) -> &ValPtr;
    }

    #[namespace = "::zeek::detail"]
    unsafe extern "C++" {
        type Frame;
    }

    #[namespace = "::zeek::plugin"]
    unsafe extern "C++" {
        include!("zeek/plugin/Plugin.h");
        type Plugin;

        type Configuration;
    }

    #[namespace = "::support"]
    unsafe extern "C++" {
        include!("plugin.h");

        type PluginWrapper;
        #[Self = "PluginWrapper"]
        #[rust_name = "new"]
        #[must_use]
        fn make(name: &str, description: &str) -> UniquePtr<PluginWrapper>;
        fn with_init_pre_execution(self: Pin<&mut PluginWrapper>, hook: fn());

        fn add_bif_item_function(
            self: Pin<&mut PluginWrapper>,
            name: &str,
            callback: fn(frame: Pin<&mut Frame>, args: &Args) -> UniquePtr<ValPtr>,
        );
    }

    unsafe extern "C++" {
        type TransportProto;
    }

    #[namespace = "::support"]
    unsafe extern "C++" {
        /// Adaptor for working with `zeek::byte_buffer`.
        ///
        /// We need this since `zeek::byte_buffer` is a `std::vector<std::byte` and `std::byte`
        /// does not map onto `u8`. Wrapping the type helps avoid running into issues with strict
        /// aliasing.
        type ByteBuffer;
        fn byte_buffer_append(vec: Pin<&mut ByteBuffer>, data: &[u8]);

        type ValPtrVector;
        #[Self = "ValPtrVector"]
        #[must_use]
        fn make(initial_capacity: usize) -> UniquePtr<ValPtrVector>;
        fn push(self: Pin<&mut ValPtrVector>, val: UniquePtr<ValPtr>);

        type TypePtrVector;
        #[Self = "TypePtrVector"]
        #[must_use]
        fn make(initial_capacity: usize) -> UniquePtr<TypePtrVector>;
        fn push(self: Pin<&mut TypePtrVector>, val: UniquePtr<TypePtr>);

        type TableIterator<'a>;
        fn next<'a>(self: &TableIterator<'a>) -> UniquePtr<TableEntry<'a>>;

        type TableEntry<'a>;
        fn key(self: &TableEntry) -> &ListVal;
        fn value(self: &TableEntry) -> *const Val;

        fn table_iter(val: &TableVal) -> UniquePtr<TableIterator<'_>>;

        fn to_addr(addr: &AddrVal) -> Addr;
        fn to_subnet(addr: &SubNetVal) -> Subnet;

        fn enum_size_val(val: &EnumVal) -> UniquePtr<ValPtr>;
        unsafe fn vec_val_at(val: &VectorVal, idx: u32) -> TypedZVal;
        unsafe fn record_get_field(val: &RecordVal, idx: i32) -> TypedZVal;

        #[must_use]
        fn make_null() -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_bool(x: bool) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_count(x: u64) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_int(x: i64) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_double(x: f64) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_string(x: &[u8]) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_pattern(exact: &str, anywhere: &str) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_interval(secs: f64) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_time(secs: f64) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_vector(xs: UniquePtr<ValPtrVector>, vector_type: &TypePtr) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_set(keys: UniquePtr<ValPtrVector>, table_type: &TypePtr) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_table(
            keys: UniquePtr<ValPtrVector>,
            values: UniquePtr<ValPtrVector>,
            table_type: &TypePtr,
        ) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_list(xs: UniquePtr<ValPtrVector>) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_addr(x: &str) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_subnet(addr: &str, prefix: u8) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_enum(x: u64, ty: &EnumType) -> UniquePtr<ValPtr>;

        #[must_use]
        fn make_port(num: u32, proto: TransportProto) -> UniquePtr<ValPtr>;

        fn make_record(
            names: &[&str],
            data: UniquePtr<ValPtrVector>,
            ty: &TypePtr,
        ) -> Result<UniquePtr<ValPtr>>;

        fn to_owned_type(ty: &TypePtr) -> UniquePtr<TypePtr>;

        #[must_use]
        fn make_vector_type(yield_: &TypePtr) -> UniquePtr<TypePtr>;

        #[must_use]
        fn make_table_type(
            key: UniquePtr<TypePtrVector>,
            val: UniquePtr<TypePtr>,
        ) -> UniquePtr<TypePtr>;
    }

    #[namespace = "::support"]
    unsafe extern "C++" {
        // Event and related accessors.
        fn event_name(event: &Event) -> &str;
        fn event_make(name: &str, args: UniquePtr<ValPtrVector>) -> Result<UniquePtr<Event>>;
        fn event_add_metadata(
            event: Pin<&mut Event>,
            id: &EnumValPtr,
            val: UniquePtr<ValPtr>,
        ) -> bool;

        #[must_use]
        fn event_registry_lookup_metadata(id: u64) -> *const EventMetadataDescriptor;

        #[must_use]
        fn event_registry_lookup_event_arg_type(name: &str, idx: usize) -> *const TypePtr;

        #[must_use]
        fn val_manager_port(port_num: u32) -> *const PortVal;

        #[must_use]
        fn zeek_id_find_type(name: &str) -> &'static TypePtr;
    }
}

/// Safe Rust type mapping Zeek's `zeek::TransportProto`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TransportProto {
    Unknown,
    Tcp,
    Udp,
    Icmp,
}

impl TryFrom<ffi::TransportProto> for TransportProto {
    type Error = Error;

    fn try_from(value: ffi::TransportProto) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            ffi::TransportProto::TRANSPORT_TCP => Self::Tcp,
            ffi::TransportProto::TRANSPORT_UDP => Self::Udp,
            ffi::TransportProto::TRANSPORT_ICMP => Self::Icmp,
            ffi::TransportProto::TRANSPORT_UNKNOWN => Self::Unknown,
            _ => Err(Error::UnknownTransportProto(value))?,
        })
    }
}

impl From<TransportProto> for ffi::TransportProto {
    fn from(value: TransportProto) -> Self {
        match value {
            TransportProto::Tcp => Self::TRANSPORT_TCP,
            TransportProto::Udp => Self::TRANSPORT_UDP,
            TransportProto::Icmp => Self::TRANSPORT_ICMP,
            TransportProto::Unknown => Self::TRANSPORT_UNKNOWN,
        }
    }
}

impl TryFrom<ffi::Addr> for IpAddr {
    type Error = Error;

    fn try_from(value: ffi::Addr) -> std::result::Result<Self, Self::Error> {
        let len = value.len;
        Ok(match len {
            4 => {
                let value = &value.bytes.as_slice()[..len.into()];
                let mut bytes: [u8; 4] = Default::default();
                bytes.copy_from_slice(value);
                IpAddr::from(bytes)
            }
            16 => {
                let value = &value.bytes.as_slice()[..len.into()];
                let mut bytes: [u8; 16] = Default::default();
                bytes.copy_from_slice(value);
                IpAddr::from(bytes)
            }
            _ => Err(Error::UnsupportedAddrSize(len))?,
        })
    }
}

impl ffi::TableVal {
    #[allow(clippy::iter_not_returning_iterator)]
    fn iter(&self) -> UniquePtr<ffi::TableIterator<'_>> {
        ffi::table_iter(self)
    }
}

impl<'a> ffi::TableEntry<'a> {
    fn value_ref(&self) -> Option<&'a ffi::Val> {
        // Unlike keys values point to raw data in the table and have a lifetime corresponding to
        // the lifetime `'a` of the iterator which is just the lifetime of the underlying table.
        unsafe { self.value().as_ref() }
    }
}

impl ffi::VectorVal {
    fn iter(&self) -> VectorValIter<'_> {
        VectorValIter {
            vec: self,
            index: 0,
            size: self.Size(),
        }
    }

    fn at(&self, idx: u32) -> TypedZVal<'_> {
        assert!(idx < self.Size(), "{} vs {}", idx, self.Size());
        let zval = unsafe { ffi::vec_val_at(self, idx) };
        TypedZVal::new(zval)
    }
}

pub struct VectorValIter<'a> {
    vec: &'a ffi::VectorVal,
    index: u32,
    size: u32,
}

impl<'a> Iterator for VectorValIter<'a> {
    type Item = TypedZVal<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.size {
            return None;
        }

        let val = self.vec.at(self.index);
        self.index += 1;

        Some(val)
    }
}

// Where a `u32` fits into a `usize` we can provide `ExactSizeIterator`.
#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl ExactSizeIterator for VectorValIter<'_> {
    fn len(&self) -> usize {
        self.size
            .try_into()
            .expect("should always be able to represent `u32` as `usize`")
    }
}

impl<'a> IntoIterator for &'a ffi::VectorVal {
    type Item = TypedZVal<'a>;
    type IntoIter = VectorValIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl From<&ffi::AddrVal> for ffi::Addr {
    fn from(value: &ffi::AddrVal) -> Self {
        ffi::to_addr(value)
    }
}

impl TryFrom<&ffi::AddrVal> for IpAddr {
    type Error = Error;

    fn try_from(value: &ffi::AddrVal) -> std::result::Result<Self, Self::Error> {
        let addr: ffi::Addr = value.into();
        addr.try_into()
    }
}

impl From<&ffi::SubNetVal> for ffi::Subnet {
    fn from(value: &ffi::SubNetVal) -> Self {
        ffi::to_subnet(value)
    }
}

/// Writer abstraction around [`support::ByteBuffer`].
pub struct ByteBufferWriter<'a> {
    inner: Pin<&'a mut ffi::ByteBuffer>,
}

impl<'a> ByteBufferWriter<'a> {
    #[must_use]
    pub fn new(value: Pin<&'a mut ffi::ByteBuffer>) -> Self {
        Self { inner: value }
    }
}

impl Write for ByteBufferWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        ffi::byte_buffer_append(self.inner.as_mut(), buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Wrap a function returning a pointer to return a ref.
#[doc(hidden)]
#[macro_export]
macro_rules! wrap_unsafe {
    ($name:ident, $unwrapped:ident, $type:ty) => {
        fn $name(&self) -> Option<&$type> {
            unsafe { self.$unwrapped().as_ref() }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! wrap_unsafe_pub {
    ($name:ident, $unwrapped:ident, $type:ty) => {
        pub fn $name(&self) -> Option<&$type> {
            unsafe { self.$unwrapped().as_ref() }
        }
    };
}

impl ffi::ValPtr {
    wrap_unsafe_pub!(val, get, ffi::Val);
}

impl ffi::TypeListPtr {
    wrap_unsafe_pub!(val, get, ffi::TypeList);
}

impl ffi::TypePtr {
    wrap_unsafe_pub!(val, get, ffi::Type);
}

impl ffi::Type {
    wrap_unsafe_pub!(as_type_list, AsTypeList, ffi::TypeList);
    wrap_unsafe_pub!(as_table_type, AsTableType, ffi::TableType);
    wrap_unsafe_pub!(as_record_type, AsRecordType, ffi::RecordType);
    wrap_unsafe_pub!(as_vector_type, AsVectorType, ffi::VectorType);
    wrap_unsafe_pub!(as_enum_type, AsEnumType, ffi::EnumType);
}

impl ffi::PatternVal {
    wrap_unsafe!(as_pattern, AsPattern, ffi::RE_Matcher);
}

impl ffi::RecordVal {
    fn get_field(&self, idx: i32) -> TypedZVal<'_> {
        let inner = unsafe { ffi::record_get_field(self, idx) };
        TypedZVal::new(inner)
    }
}

impl ffi::RecordType {
    pub fn field_name(&self, i: i32) -> Option<std::result::Result<&str, str::Utf8Error>> {
        let name = self.FieldName(i);
        if name.is_null() {
            return None;
        }

        Some(unsafe { CStr::from_ptr(name).to_str() })
    }

    /// # Panics
    ///
    /// - `field_name` must not contain embedded null bytes
    pub fn get_field_type(&self, field_name: &str) -> Option<&ffi::TypePtr> {
        let field_name =
            CString::new(field_name).expect("field names should not contain embedded null bytes");
        let field_name = field_name.as_ptr();

        let field_index = unsafe { self.FieldOffset(field_name) };
        if field_index < 0 {
            return None;
        }

        Some(unsafe { self.GetFieldType(field_index) })
    }
}

impl ffi::Event {
    wrap_unsafe!(metadata, Metadata, CxxVector<ffi::MetadataEntry>);
}

impl ffi::RE_Matcher {
    fn pattern_text(&self) -> std::result::Result<&str, str::Utf8Error> {
        let ptr = self.PatternText();
        assert!(!ptr.is_null());
        unsafe { CStr::from_ptr(ptr) }.to_str()
    }

    fn anywhere_pattern_text(&self) -> std::result::Result<&str, str::Utf8Error> {
        let ptr = self.AnywherePatternText();
        assert!(!ptr.is_null());
        unsafe { CStr::from_ptr(ptr) }.to_str()
    }
}

fn event_registry_lookup_event_arg_type(name: &str, idx: usize) -> Option<&ffi::TypePtr> {
    unsafe { ffi::event_registry_lookup_event_arg_type(name, idx).as_ref() }
}

fn event_registry_lookup_metadata(id: u64) -> Option<&'static ffi::EventMetadataDescriptor> {
    unsafe { ffi::event_registry_lookup_metadata(id).as_ref() }
}

unsafe impl Send for ffi::PluginWrapper {}
unsafe impl Sync for ffi::PluginWrapper {}
