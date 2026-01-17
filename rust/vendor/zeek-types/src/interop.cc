#include "interop.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <zeek/ID.h>

#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

#include "zeek/script_opt/CPP/RuntimeOps.h"

#ifdef CORROSION_BUILD
#include "zeek_types_cxx/lib.h"
#else
#include "zeek_types_cxx/src/lib.rs.h"
#endif

namespace support {

std::unique_ptr<TableIterator> table_iter(const zeek::TableVal &table) {
  return std::make_unique<TableIterator>(table);
}

Addr to_addr(const zeek::IPAddr &addr) {
  const uint8_t *data = nullptr;
  auto len = addr.GetBytes(reinterpret_cast<const uint32_t **>(&data)) * 4;

  Addr result;
  result.len = len;

  std::copy_n(data, len, result.bytes.begin());

  return result;
}

Addr to_addr(const zeek::AddrVal &val) { return to_addr(val.Get()); }

Subnet to_subnet(const zeek::SubNetVal &val) {
  auto addr = to_addr(val.Prefix());

  return Subnet{.prefix = addr, .width = val.Width()};
}

TypedZVal vec_val_at(const zeek::VectorVal &xs, unsigned int idx) {
  auto nil = TypedZVal{.val = nullptr, .type_ = nullptr};
  if (idx >= xs.Size())
    return nil;

  const auto &x = xs.RawVec()[idx];
  if (!x)
    return nil;

  const auto &yield_type = xs.RawYieldType();
  auto *yield_types = xs.RawYieldTypes();
  const auto &ty = yield_types ? (*yield_types)[idx] : yield_type;
  if (!ty)
    return nil;

  return TypedZVal{.val = &*x, .type_ = ty.get()};
}

std::unique_ptr<zeek::ValPtr> enum_size_val(const zeek::EnumVal &x) {
  // Needed since `SizeVal` returns a value.
  // TODO(bbannier): Change Zeek definition to return a `const` ref.
  auto val = x.SizeVal();
  return std::make_unique<zeek::ValPtr>(val);
}

TypedZVal record_get_field(const zeek::RecordVal &rec, int32_t field) {
  auto nil = TypedZVal{.val = nullptr, .type_ = nullptr};

  if (!rec.HasField(field))
    // Field unset.
    return nil;

  const auto *rt = rec.GetType()->AsRecordType();

  if (field >= rt->NumFields())
    // Field unknown.
    return nil;

  // To get the actual ZVal we need to use script_opt's `CPPRuntime`
  // since it is a friend of `RecordVal` 🤦.
  //
  // TODO(bbannier): Change `RecordVal::RawOptField` from `protected` to
  // `public` (the class is `final` anyway). When we do that `RecordVal` can
  // also unfriend `CPPRuntime`.
  zeek::detail::CPPRuntime runtime;
  const auto &x = runtime.RawField(&const_cast<zeek::RecordVal &>(rec), field);

  const auto &ty = rt->GetFieldType(field);
  if (!ty)
    return nil;

  return TypedZVal{.val = &x, .type_ = ty.get()};
}

std::unique_ptr<zeek::ValPtr> make_vector(std::unique_ptr<ValPtrVector> xs,
                                          const zeek::TypePtr &vector_type) {
  if (!xs)
    return nullptr;

  auto ty = zeek::cast_intrusive<zeek::VectorType>(vector_type);
  auto result = zeek::make_intrusive<zeek::VectorVal>(std::move(ty));

  auto &&vals = std::move(*xs).data();
  result->Resize(vals.size());

  for (size_t i = 0; i < vals.size(); ++i) {
    if (auto &&val = std::move(vals[i]))
      result->Assign(i, std::move(val));
  }

  return wrap(std::move(result));
}

std::unique_ptr<zeek::ValPtr> make_list(std::unique_ptr<ValPtrVector> xs) {
  auto list = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);

  std::ranges::for_each(std::move(*xs).data(), [&](auto &&x) {
    list->Append(std::forward<decltype(x)>(x));
  });

  return wrap(list);
}

std::unique_ptr<zeek::TypePtr> to_owned_type(const zeek::TypePtr &ty) {
  return std::make_unique<zeek::TypePtr>(ty);
}

std::unique_ptr<zeek::ValPtr> make_null() { return wrap(zeek::Val::nil); }
std::unique_ptr<zeek::ValPtr> make_bool(bool x) {
  return wrap(zeek::val_mgr->Bool(x));
}
std::unique_ptr<zeek::ValPtr> make_count(uint64_t x) {
  return wrap(zeek::val_mgr->Count(x));
}
std::unique_ptr<zeek::ValPtr> make_int(int64_t x) {
  return wrap(zeek::val_mgr->Int(x));
}
std::unique_ptr<zeek::ValPtr> make_double(double x) {
  return wrap(zeek::make_intrusive<zeek::DoubleVal>(x));
}
std::unique_ptr<zeek::ValPtr> make_time(double x) {
  return wrap(zeek::make_intrusive<zeek::TimeVal>(x));
}
std::unique_ptr<zeek::ValPtr> make_interval(double x) {
  return wrap(zeek::make_intrusive<zeek::IntervalVal>(x));
}

std::unique_ptr<zeek::ValPtr> make_pattern(rust::Str exact_,
                                           rust::Str anywhere_) {
  auto exact = std::string{exact_.begin(), exact_.end()};
  auto anywhere = std::string{anywhere_.begin(), anywhere_.end()};

  // Passing a reference to a temporary is safe since
  // `RE_Matcher` internally copies the data.
  auto re = std::make_unique<zeek::RE_Matcher>(exact.c_str(), anywhere.c_str());
  return wrap(zeek::make_intrusive<zeek::PatternVal>(re.release()));
}

std::unique_ptr<zeek::ValPtr> make_string(rust::Slice<const uint8_t> x) {
  if (x.empty())
    return wrap(zeek::val_mgr->EmptyString());

  return wrap(zeek::make_intrusive<zeek::StringVal>(
      x.length(), reinterpret_cast<const char *>(x.data())));
}

std::unique_ptr<zeek::ValPtr> make_addr(rust::Str addr_) {
  std::string addr{addr_.begin(), addr_.end()};
  return wrap(zeek::make_intrusive<zeek::AddrVal>(addr));
}

std::unique_ptr<zeek::ValPtr> make_subnet(rust::Str addr_, uint8_t prefix) {
  std::string s{addr_.begin(), addr_.end()};

  return wrap(zeek::make_intrusive<zeek::SubNetVal>(
      zeek::IPPrefix{zeek::IPAddr{s.c_str()}, prefix}));
}

std::unique_ptr<zeek::ValPtr> make_enum(uint64_t x, const zeek::EnumType &ty_) {
  return wrap(const_cast<zeek::EnumType &>(ty_).GetEnumVal(x));
}
std::unique_ptr<zeek::ValPtr> make_port(uint32_t num, TransportProto proto) {
  return wrap(zeek::val_mgr->Port(num, proto));
}

struct UnknownField : std::runtime_error {
  UnknownField(std::string_view name)
      : std::runtime_error(std::format("unknown field {}", name)) {}
};

std::unique_ptr<zeek::ValPtr> make_record(rust::Slice<const rust::Str> names,
                                          std::unique_ptr<ValPtrVector> data_,
                                          const zeek::TypePtr &record_type) {
  auto t = cast_intrusive<zeek::RecordType>(record_type);
  auto rec = zeek::make_intrusive<zeek::RecordVal>(t);

  auto data = std::move(*data_).data();

  for (size_t i = 0; i < names.size(); ++i) {
    const auto &n = names[i];
    auto name = std::string{n.data(), n.size()};
    auto idx = t->FieldOffset(name.c_str());
    if (idx < 0)
      throw UnknownField(name.data());

    rec->Assign(idx, std::move(data[i]));
  }

  return wrap(std::move(rec));
}

struct KeyValueInconsistent : std::runtime_error {
  KeyValueInconsistent(size_t num_keys, size_t num_values)
      : std::runtime_error(
            std::format("number of keys and values is inconsistent: {} vs. {}",
                        num_keys, num_values)) {}
};

std::unique_ptr<zeek::ValPtr> make_set(std::unique_ptr<ValPtrVector> keys_,
                                       const zeek::TypePtr &table_type) {
  auto ty = zeek::cast_intrusive<zeek::TableType>(table_type);

  auto t = zeek::make_intrusive<zeek::TableVal>(std::move(ty));

  auto keys = std::move(*keys_).data();

  for (auto &k : keys) {
    t->Assign(std::move(k), nullptr);
  }

  return wrap(std::move(t));
}

std::unique_ptr<zeek::ValPtr> make_table(std::unique_ptr<ValPtrVector> keys_,
                                         std::unique_ptr<ValPtrVector> values_,
                                         const zeek::TypePtr &table_type) {
  auto ty = zeek::cast_intrusive<zeek::TableType>(table_type);
  auto t = zeek::make_intrusive<zeek::TableVal>(std::move(ty));

  auto keys = std::move(*keys_).data();
  auto values = std::move(*values_).data();

  if (keys.size() != values.size())
    throw KeyValueInconsistent(keys.size(), values.size());

  for (size_t i = 0; i < keys.size(); ++i) {
    auto &k = keys[i];
    auto &v = values[i];
    t->Assign(std::move(k), std::move(v));
  }

  return wrap(std::move(t));
}

std::unique_ptr<zeek::TypePtr> make_vector_type(const zeek::TypePtr &yield) {
  auto ty = zeek::make_intrusive<zeek::VectorType>(yield);
  return std::make_unique<zeek::TypePtr>(ty);
}

std::unique_ptr<zeek::TypePtr>
make_table_type(std::unique_ptr<TypePtrVector> key_,
                std::unique_ptr<zeek::TypePtr> val) {
  auto key = zeek::make_intrusive<zeek::TypeList>();
  std::ranges::for_each(std::move(*key_).data(),
                        [&](auto &&x) { key->Append(x); });

  auto yield = val ? std::move(*val) : nullptr;
  return std::make_unique<zeek::TypePtr>(
      zeek::make_intrusive<zeek::TableType>(key, std::move(yield)));
}

void byte_buffer_append(ByteBuffer &vec, rust::Slice<const uint8_t> data) {
  auto size = vec.size();
  vec.resize(size + data.size());
  std::memcpy(vec.data() + size, data.data(), data.size());
}

rust::Str event_name(const zeek::cluster::Event &event) {
  auto name = event.HandlerName();
  return rust::Str{name.data(), name.size()};
}

struct UnknownEvent : std::runtime_error {
  UnknownEvent(std::string_view name)
      : std::runtime_error(std::format("unknown event {}", name)) {}
};

std::unique_ptr<zeek::cluster::Event>
event_make(rust::Str name_, std::unique_ptr<support::ValPtrVector> args_) {
  auto name = std::string_view{name_.data(), name_.size()};
  auto *handler = zeek::event_registry->Lookup(name);
  if (!handler)
    throw UnknownEvent(name);

  zeek::Args args;
  if (args_)
    args = std::move(*args_).data();

  auto event = zeek::cluster::Event(handler, std::move(args), {});
  return std::make_unique<zeek::cluster::Event>(std::move(event));
}

bool event_add_metadata(zeek::cluster::Event &event, const zeek::EnumValPtr &id,
                        std::unique_ptr<zeek::ValPtr> val) {
  return event.AddMetadata(id, std::move(*val));
}

const zeek::EventMetadataDescriptor *
event_registry_lookup_metadata(uint64_t id) {
  return zeek::event_registry->LookupMetadata(id);
}

zeek::TypePtr const *event_registry_lookup_event_arg_type(rust::Str name_,
                                                          size_t idx) {
  auto name = std::string_view{name_.data(), name_.size()};

  auto *handler = zeek::event_registry->Lookup(name);
  if (!handler)
    return nullptr;

  auto &&ty = handler->GetType();
  if (!ty)
    return nullptr;

  auto &&params = ty->Params();
  if (!params)
    return nullptr;

  return &params->GetFieldType(idx);
}

const zeek::PortVal *val_manager_port(uint32_t port_num) {
  return zeek::val_mgr->Port(port_num).get();
}

const zeek::TypePtr &zeek_id_find_type(rust::Str name_) {
  auto name = std::string_view{name_.begin(), name_.end()};
  return zeek::id::find_type(name);
}

} // namespace support
