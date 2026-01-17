#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "zeek/CompHash.h"
#include "zeek/Dict.h"
#include "zeek/EventRegistry.h"
#include "zeek/ID.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"
#include "zeek/cluster/Event.h"

#include "rust/cxx.h"

using zeek::TypeTag;

struct Addr;
struct Subnet;
struct TypedZVal;

template <typename T> inline auto wrap(T &&x) {
  return std::make_unique<zeek::ValPtr>(std::forward<T>(x));
}

namespace support {

using ByteBuffer = std::vector<std::byte>;

class TableEntry {
public:
  TableEntry(zeek::ListValPtr key, zeek::ValPtr value)
      : key_(std::move(key)), value_(std::move(value)) {}

  TableEntry(TableEntry &&) = default;

  const zeek::ListVal &key() const { return *key_; }
  const zeek::Val *value() const { return value_.get(); }

private:
  zeek::ListValPtr key_;
  zeek::ValPtr value_;
};

// Helper class to pass a vector of unique_ptr by value from Rust to C++.
template <typename T> class PtrVector {
  std::vector<T> vals;

public:
  PtrVector() = default;
  PtrVector(const PtrVector &) = delete;
  PtrVector(PtrVector &&b) noexcept { std::swap(this->vals, b.vals); }

  void push(std::unique_ptr<T> x) { vals.emplace_back(std::move(*x)); }

  static auto make(size_t initial_capacity) {
    auto xs = std::make_unique<PtrVector>();
    xs->vals.reserve(initial_capacity);
    return xs;
  }

  auto size() const { return vals.size(); }
  auto data() && { return std::move(vals); }
};

using ValPtrVector = PtrVector<zeek::ValPtr>;
using TypePtrVector = PtrVector<zeek::TypePtr>;

struct TableIterator {
  TableIterator(const zeek::TableVal &table) : dict(table.Get()) {
    if (dict) {
      cur = dict->begin();
      end = dict->end();
      h = table.GetTableHash();
    }
  }

  std::unique_ptr<TableEntry> next() const {
    // We _have_ to return a value and not a ref/ptr
    // here since the current entry is a local value.
    //
    // TODO(bbannier): Figure out a way to return a ref (with `ZVals`?).
    if (!dict || cur == end)
      return nullptr;

    auto &val = *cur++;

    auto key = h->RecoverVals(*val.GetHashKey());
    const auto &value = val.value->GetVal();

    return std::make_unique<TableEntry>(std::move(key), value);
  }

  const zeek::PDict<zeek::TableEntryVal> *dict = nullptr;

  mutable zeek::DictIterator<zeek::TableEntryVal> cur;
  zeek::DictIterator<zeek::TableEntryVal> end;

  const zeek::detail::CompositeHash *h;
};

std::unique_ptr<TableIterator> table_iter(const zeek::TableVal &table);

Addr to_addr(const zeek::AddrVal &val);
Subnet to_subnet(const zeek::SubNetVal &val);

std::unique_ptr<zeek::ValPtr> enum_size_val(const zeek::EnumVal &x);
TypedZVal vec_val_at(const zeek::VectorVal &xs, unsigned int idx);
TypedZVal record_get_field(const zeek::RecordVal &val, int32_t field);

const std::vector<zeek::TypePtr> &table_indices(const zeek::TableType &ty);

std::unique_ptr<zeek::TypeList>
make_typelist(rust::Slice<zeek::TypePtr *const> xs);

std::unique_ptr<zeek::TypePtr> to_owned_type(const zeek::TypePtr &ty);

std::unique_ptr<zeek::ValPtr> make_null();
std::unique_ptr<zeek::ValPtr> make_bool(bool x);
std::unique_ptr<zeek::ValPtr> make_count(uint64_t x);
std::unique_ptr<zeek::ValPtr> make_int(int64_t x);
std::unique_ptr<zeek::ValPtr> make_double(double x);
std::unique_ptr<zeek::ValPtr> make_string(rust::Slice<const uint8_t> x);
std::unique_ptr<zeek::ValPtr> make_pattern(rust::Str exact, rust::Str anywhere);
std::unique_ptr<zeek::ValPtr> make_interval(double x);
std::unique_ptr<zeek::ValPtr> make_time(double x);
std::unique_ptr<zeek::ValPtr> make_vector(std::unique_ptr<ValPtrVector> xs,
                                          const zeek::TypePtr &vector_type);
std::unique_ptr<zeek::ValPtr> make_list(std::unique_ptr<ValPtrVector> xs);
std::unique_ptr<zeek::ValPtr> make_addr(rust::Str x);
std::unique_ptr<zeek::ValPtr> make_subnet(rust::Str x, uint8_t prefix);
std::unique_ptr<zeek::ValPtr> make_enum(uint64_t x, const zeek::EnumType &ty);
std::unique_ptr<zeek::ValPtr> make_port(uint32_t num, TransportProto proto);
std::unique_ptr<zeek::ValPtr> make_record(rust::Slice<const rust::Str> names,
                                          std::unique_ptr<ValPtrVector> data,
                                          const zeek::TypePtr &record_type);
std::unique_ptr<zeek::ValPtr> make_set(std::unique_ptr<ValPtrVector> keys,
                                       const zeek::TypePtr &table_type);
std::unique_ptr<zeek::ValPtr> make_table(std::unique_ptr<ValPtrVector> keys,
                                         std::unique_ptr<ValPtrVector> values,
                                         const zeek::TypePtr &table_type);

std::unique_ptr<zeek::TypePtr> make_vector_type(const zeek::TypePtr &yield);
std::unique_ptr<zeek::TypePtr>
make_table_type(std::unique_ptr<TypePtrVector> key,
                std::unique_ptr<zeek::TypePtr> val);

std::unique_ptr<zeek::TypePtr> to_owned_type(const zeek::TypePtr &ty);

std::unique_ptr<zeek::TypePtr> make_vector_type(const zeek::TypePtr &yield);
std::unique_ptr<zeek::TypePtr>
make_table_type(std::unique_ptr<TypePtrVector> key,
                std::unique_ptr<zeek::TypePtr> val);

void byte_buffer_append(ByteBuffer &vec, rust::Slice<const uint8_t> data);

rust::Str event_name(const zeek::cluster::Event &event);

std::unique_ptr<zeek::cluster::Event>
event_make(rust::Str name, std::unique_ptr<support::ValPtrVector> args);

bool event_add_metadata(zeek::cluster::Event &event, const zeek::EnumValPtr &id,
                        std::unique_ptr<zeek::ValPtr> val);

const zeek::EventMetadataDescriptor *
event_registry_lookup_metadata(uint64_t id);

zeek::TypePtr const *event_registry_lookup_event_arg_type(rust::Str name,
                                                          size_t idx);

const zeek::PortVal *val_manager_port(uint32_t port_num);

const zeek::TypePtr &zeek_id_find_type(rust::Str name);

} // namespace support
