use std::marker::PhantomData;

use crate::{
    Error, Result, Val, ffi,
    val::{ValConvert, ValInterface},
};

pub struct TypedZVal<'a> {
    inner: ffi::TypedZVal,
    phantom: PhantomData<&'a ffi::TypedZVal>,
}

impl<'a> TypedZVal<'a> {
    #[must_use]
    pub fn new(raw: ffi::TypedZVal) -> Self {
        Self {
            inner: raw,
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn type_(&self) -> Option<&'a ffi::Type> {
        unsafe { self.inner.type_.as_ref() }
    }

    #[must_use]
    pub fn value(&self) -> Option<&'a ffi::ZVal> {
        unsafe { self.inner.val.as_ref() }
    }
}

impl<'a> TryFrom<&'a TypedZVal<'a>> for Val<'a> {
    type Error = Error;

    fn try_from(val: &'a TypedZVal) -> Result<Self> {
        val.value().map_or(Ok(Val::None), |v| {
            <Val<'a> as ValConvert<&ffi::ZVal>>::convert(v, val.type_().ok_or(Error::ValueUnset)?)
        })
    }
}

impl ValInterface for ffi::ZVal {
    fn as_any(&self) -> Option<&ffi::Val> {
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

    fn as_string_val(&self) -> Option<&ffi::StringVal> {
        unsafe { self.AsString().as_ref() }
    }

    fn as_port_val(&self) -> Option<&ffi::PortVal> {
        let port_num = self.AsInt().try_into().ok()?;
        unsafe { ffi::val_manager_port(port_num).as_ref() }
    }

    fn as_addr_val(&self) -> Option<&ffi::AddrVal> {
        unsafe { self.AsAddr().as_ref() }
    }

    fn as_subnet_val(&self) -> Option<&ffi::SubNetVal> {
        unsafe { self.AsSubNet().as_ref() }
    }

    fn as_vector_val(&self) -> Option<&ffi::VectorVal> {
        unsafe { self.AsVector().as_ref() }
    }

    fn as_enum(&self) -> Result<u64> {
        Ok(self.AsInt().try_into()?)
    }

    fn as_pattern_val(&self) -> Option<&ffi::PatternVal> {
        unsafe { self.AsPattern().as_ref() }
    }

    fn as_table_val(&self) -> Option<&ffi::TableVal> {
        unsafe { self.AsTable().as_ref() }
    }

    fn as_record_val(&self) -> Option<&ffi::RecordVal> {
        unsafe { self.AsRecord().as_ref() }
    }

    fn as_list_val(&self) -> Option<&ffi::ListVal> {
        unsafe { self.AsList().as_ref() }
    }
}
