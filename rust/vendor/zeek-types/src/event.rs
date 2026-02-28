use std::collections::BTreeMap;

use cxx::UniquePtr;

use crate::{
    Error, Result, Val, event_registry_lookup_event_arg_type, event_registry_lookup_metadata, ffi,
};

/// Rust type modelling `zeek::cluster::Event`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Event<'a> {
    pub name: &'a str,
    pub args: Vec<Val<'a>>,
    pub meta: BTreeMap<u64, Val<'a>>,
}

impl<'a> TryFrom<&'a ffi::Event> for Event<'a> {
    type Error = Error;

    fn try_from(event: &'a ffi::Event) -> std::result::Result<Self, Self::Error> {
        let name = ffi::event_name(event);

        let args = event.Args();
        let args: Result<_> = (0..args.size())
            .map(|idx| {
                let x = args.at(idx).val();
                let Some(x) = x else { return Ok(Val::None) };
                Val::try_from(x)
            })
            .collect();
        let args = args?;

        let meta = match event.metadata() {
            None => BTreeMap::default(),
            Some(meta) => {
                let meta: Result<_> = meta
                    .into_iter()
                    .map(|entry| {
                        let val = match entry.Val().val() {
                            None => Val::None,
                            Some(v) => v.try_into()?,
                        };
                        Ok::<_, Error>((entry.Id(), val))
                    })
                    .collect();

                meta?
            }
        };

        Ok(Self { name, args, meta })
    }
}

impl TryFrom<Event<'_>> for UniquePtr<ffi::Event> {
    type Error = Error;

    fn try_from(Event { name, args, meta }: Event) -> std::result::Result<Self, Self::Error> {
        let mut args_ = ffi::ValPtrVector::make(args.len());
        for (idx, x) in args.into_iter().enumerate() {
            let ty = event_registry_lookup_event_arg_type(name, idx)
                .ok_or_else(|| Error::UnknownEventArgType(idx, name.to_owned()))?;
            args_.pin_mut().push(x.to_valptr(Some(ty))?);
        }

        let mut event = ffi::event_make(name, args_)?;

        for (id, meta) in meta {
            let id = event_registry_lookup_metadata(id).ok_or(Error::UnknownMetadataId(id))?;
            ffi::event_add_metadata(
                event.pin_mut(),
                id.IdVal(),
                meta.to_valptr(Some(id.Type()))?,
            );
        }

        Ok(event)
    }
}
