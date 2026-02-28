use std::marker::PhantomData;

use crate::{
    Error, Result, Val, support,
    val::{ValConvert, ValInterface},
    zeek,
};

/// Rust wrapper around a [`support::TypedZVal`].
pub struct TypedZVal<'a> {
    inner: support::TypedZVal,
    phantom: PhantomData<&'a support::TypedZVal>,
}

impl<'a> TypedZVal<'a> {
    #[must_use]
    pub fn new(raw: support::TypedZVal) -> Self {
        Self {
            inner: raw,
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn type_(&self) -> Option<&'a zeek::Type> {
        unsafe { self.inner.type_.as_ref() }
    }

    #[must_use]
    pub fn value(&self) -> Option<&'a zeek::ZVal> {
        unsafe { self.inner.val.as_ref() }
    }
}

impl<'a> TryFrom<&'a TypedZVal<'a>> for Val<'a> {
    type Error = Error;

    fn try_from(val: &'a TypedZVal) -> Result<Self> {
        val.value().map_or(Ok(Val::None), |v| {
            <Val<'a> as ValConvert<&zeek::ZVal>>::convert(v, val.type_().ok_or(Error::ValueUnset)?)
        })
    }
}

impl ValInterface for zeek::ZVal {
    fn as_any(&self) -> Option<&zeek::Val> {
        unsafe { self.AsAny().as_ref() }
    }

    fn as_bool(&self) -> bool {
        self.AsInt() != 0
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
        self.AsDouble()
    }

    fn as_time(&self) -> f64 {
        self.AsDouble()
    }

    fn as_string_val(&self) -> Option<&zeek::StringVal> {
        unsafe { self.AsString().as_ref() }
    }

    fn as_port_val(&self) -> Option<&zeek::PortVal> {
        let port_num = self.AsInt().try_into().ok()?;
        unsafe { support::val_manager_port(port_num).as_ref() }
    }

    fn as_addr_val(&self) -> Option<&zeek::AddrVal> {
        unsafe { self.AsAddr().as_ref() }
    }

    fn as_subnet_val(&self) -> Option<&zeek::SubNetVal> {
        unsafe { self.AsSubNet().as_ref() }
    }

    fn as_vector_val(&self) -> Option<&zeek::VectorVal> {
        unsafe { self.AsVector().as_ref() }
    }

    fn as_enum(&self) -> Result<u64> {
        Ok(self.AsInt().try_into()?)
    }

    fn as_pattern_val(&self) -> Option<&zeek::PatternVal> {
        unsafe { self.AsPattern().as_ref() }
    }

    fn as_table_val(&self) -> Option<&zeek::TableVal> {
        unsafe { self.AsTable().as_ref() }
    }

    fn as_record_val(&self) -> Option<&zeek::RecordVal> {
        unsafe { self.AsRecord().as_ref() }
    }

    fn as_list_val(&self) -> Option<&zeek::ListVal> {
        unsafe { self.AsList().as_ref() }
    }
}
