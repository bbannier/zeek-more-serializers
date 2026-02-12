#include "Plugin.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <numeric>
#include <optional>
#include <ranges>
#include <unordered_map>
#include <vector>
#include <zeek/IntrusivePtr.h>
#include <zeek/Reporter.h>
#include <zeek/Val.h>
#include <zeek/cluster/Backend.h>
#include <zeek/cluster/BifSupport.h>
#include <zeek/util-types.h>

#include "zeek/broker/Manager.h"
#include "zeek/cluster/Component.h"
#include "zeek/cluster/Event.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/serializer/broker/Serializer.h"
#include "zeek/logging/Types.h"
#include "zeek/storage/Component.h"
#include "zeek/storage/Serializer.h"
#include "zeek/storage/serializer/json/JSON.h"

#include "config.h"
#include "zeek_more_serializers_cxx/lib.h"

namespace {

std::string format_name_string(Format format) {
  auto n = format_name(format);
  return {n.data(), n.size()};
}

namespace storage {

template <Format format> struct Serializer : zeek::storage::Serializer {
  Serializer() : zeek::storage::Serializer(format_name_string(format)) {}

  static std::unique_ptr<zeek::storage::Serializer> Instantiate() {
    return std::make_unique<Serializer>();
  }

  std::optional<zeek::byte_buffer> Serialize(zeek::ValPtr val) override {
    if (!val)
      return std::nullopt;

    zeek::byte_buffer buf;

    try {
      serialize_val(*val.get(), format, buf);
      return {std::move(buf)};
    } catch (const std::exception &e) {
      zeek::reporter->Error("%s", e.what());
      return {};
    }
  }

  zeek::expected<zeek::ValPtr, std::string>
  Unserialize(zeek::byte_buffer_span buf, zeek::TypePtr type) override {
    static_assert(sizeof(zeek::byte_buffer::value_type) == sizeof(uint8_t));
    auto data = rust::Slice<const uint8_t>{
        reinterpret_cast<const uint8_t *>(buf.data()), buf.size_bytes()};

    try {
      auto deserialized = deserialize_val(data, format, type);
      auto val = std::move(*deserialized.get());
      return val;
    } catch (const std::exception &e) {
      return zeek::unexpected<std::string>(e.what());
    }
  }
};

} // namespace storage

namespace cluster {

namespace event {

// TODO(bbannier): This needs tests.
template <Format format> struct Serializer : zeek::cluster::EventSerializer {
  Serializer() : zeek::cluster::EventSerializer(format_name_string(format)) {}

  static std::unique_ptr<zeek::cluster::EventSerializer> Instantiate() {
    return std::make_unique<Serializer>();
  }

  bool SerializeEvent(zeek::byte_buffer &buf,
                      const zeek::cluster::Event &event) override {
    try {
      serialize_event(event, format, buf);
      return true;
    } catch (const std::exception &e) {
      zeek::reporter->Warning("failed to serialize event: %s", e.what());
      return false;
    }
  }

  std::optional<zeek::cluster::Event>
  UnserializeEvent(zeek::byte_buffer_span buf) override {
    zeek::cluster::Event *e;
    auto data = rust::Slice<const uint8_t>{
        reinterpret_cast<const uint8_t *>(buf.data()), buf.size_bytes()};
    try {
      auto event = deserialize_event(data, format);
      assert(event);
      return std::move(*event);
    } catch (const std::exception &e) {
      zeek::reporter->Warning("failed to deserialize event: %s", e.what());
      return std::nullopt;
    }
  }
};

} // namespace event

namespace log {

// TODO(bbannier): This needs either whole modelling of `threading::Value`,
// or implementing a conversion from `Val` to `threading::Value` (the other
// way around works out of the box with `ValueToVal`).
template <Format format> struct Serializer : zeek::cluster::LogSerializer {
  Serializer() : zeek::cluster::LogSerializer(format_name_string(format)) {}

  bool SerializeLogWrite(
      zeek::byte_buffer &buf,
      const zeek::logging::detail::LogWriteHeader &header,
      std::span<zeek::logging::detail::LogRecord> records) override {
    abort();
  }

  std::optional<zeek::logging::detail::LogWriteBatch>
  UnserializeLogWrite(zeek::byte_buffer_span buf) override {
    abort();
  }
};

} // namespace log

} // namespace cluster

} // namespace

namespace Zeek_more_serializers {
Plugin plugin;
} // namespace Zeek_more_serializers

zeek::plugin::Configuration Zeek_more_serializers::Plugin::Configure() {
  AddComponent(new zeek::storage::SerializerComponent(
      "binary", storage::Serializer<Format::Binary>::Instantiate));
  AddComponent(new zeek::cluster::EventSerializerComponent(
      "binary", cluster::event::Serializer<Format::Binary>::Instantiate));

  AddComponent(new zeek::storage::SerializerComponent(
      "human", storage::Serializer<Format::Human>::Instantiate));
  AddComponent(new zeek::cluster::EventSerializerComponent(
      "human", cluster::event::Serializer<Format::Human>::Instantiate));

  zeek::plugin::Configuration config;
  config.name = "Zeek::more_serializers";
  config.description = "Additional serializers";
  config.version.major = VERSION_MAJOR;
  config.version.minor = VERSION_MINOR;
  config.version.patch = VERSION_PATCH;
  return config;
}

namespace Zeek_more_serializers::detail::benchmark {

namespace {
using Duration = std::chrono::duration<double>;
using Measurements = std::vector<Duration>;
using Timinig = std::unordered_map<std::string, Measurements>;

Duration mean(const Measurements &xs) {
  auto n = xs.size();
  return std::accumulate(xs.begin(), xs.end(), Duration()) / n;
}

Duration mean_err(const Measurements &xs, const Duration &mean) {
  auto n = xs.size();

  auto v =
      xs | std::views::transform([&](const std::chrono::duration<double> &x) {
        return std::pow((x - mean).count(), 2);
      });
  return Duration{std::sqrt(std::accumulate(v.begin(), v.end(), 0.))};
}

void summarize(std::string_view suite, const Timinig &t_serialize,
               const Timinig &t_deserialize) {

  for (auto &&[name, xs] : t_serialize) {
    auto bench = "ser";
    for (auto &&x : xs)
      std::cout << std::format("{}\t{}\t{}\t{}\n", bench, suite, name,
                               x.count());
  }

  for (auto &&[name, xs] : t_deserialize) {
    auto bench = "de";
    for (auto &&x : xs)
      std::cout << std::format("{}\t{}\t{}\t{}\n", bench, suite, name,
                               x.count());
  }

  // std::cout << "#suite name n t_serialize dt_serialize t_deserialize "
  //              "dt_deserialize\n";

  // for (auto &&[name, dt] : t_serialize) {
  //   auto n = dt.size();
  //   auto mean_serialize = mean(dt);
  //   auto sig_serialize = mean_err(dt, mean_serialize);

  //   auto &de = t_deserialize.at(name);
  //   assert(de.size() == n);
  //   auto mean_deserialize = mean(de);
  //   auto sig_deserialize = mean_err(dt, mean_deserialize);

  //   std::cout << suite << '\t' << name << '\t' << n << '\t' << mean_serialize
  //             << '\t' << sig_serialize << '\t' << mean_deserialize << '\t'
  //             << sig_deserialize << '\n';
  // }
}

size_t benchmark_iterations() {
  size_t result = 1;

  if (auto n = ::getenv("BENCHMARK_NUM")) {
    auto len = ::strlen(n);
    auto num = std::string_view{n, len};
    std::from_chars(num.begin(), num.end(), result);
  }

  return result;
}

} // namespace

void bench_storage(zeek::StringVal *suite, const zeek::Val &val_) {
  auto val = const_cast<zeek::Val &>(val_).Clone();

  std::unordered_map<std::string, std::unique_ptr<zeek::storage::Serializer>>
      serializers;
  serializers.emplace("binary",
                      storage::Serializer<Format::Binary>::Instantiate());
  serializers.emplace("human",
                      storage::Serializer<Format::Human>::Instantiate());
  serializers.emplace("zeek_json",
                      zeek::storage::serializer::json::JSON::Instantiate());

  Timinig t_serialize;
  Timinig t_deserialize;

  for (auto &[name, serializer] : serializers) {
    for (int i = 0; i < benchmark_iterations(); ++i) {
      // Serialize.
      auto start = std::chrono::high_resolution_clock::now();
      auto x = serializer->Serialize(val);
      auto end = std::chrono::high_resolution_clock::now();
      t_serialize[name].emplace_back(end - start);

      const auto &type = val->GetType();

      assert(x);
      start = std::chrono::high_resolution_clock::now();
      auto _ = serializer->Unserialize(*x, type);
      end = std::chrono::high_resolution_clock::now();
      t_deserialize[name].emplace_back(end - start);
    }
  }

  summarize(suite->ToStdStringView(), t_serialize, t_deserialize);
}

void bench_event(zeek::StringVal *suite, const zeek::ValPtr &topic,
                 zeek::ArgsSpan args) {
  static const auto &cluster_event_type =
      zeek::id::find_type<zeek::RecordType>("Cluster::Event");

  if (args.size() != 1 || args[0]->GetType() != cluster_event_type) {
    zeek::reporter->Error("expected a cluster event as only parameter");
    return;
  }

  auto *rec = args[0]->AsRecordVal();
  assert(rec);

  const auto &func = rec->GetField<zeek::FuncVal>(0);
  const auto &vargs = rec->GetField<zeek::VectorVal>(1);

  // Need to copy from VectorVal to zeek::Args
  zeek::Args args_(vargs->Size());
  for (size_t i = 0; i < vargs->Size(); i++)
    args_[i] = vargs->ValAt(i);

  auto event = zeek::broker_mgr->MakeClusterEvent(func, args_);
  assert(event);

  std::unordered_map<std::string,
                     std::unique_ptr<zeek::cluster::EventSerializer>>
      serializers;
  serializers.emplace(
      "binary", cluster::event::Serializer<Format::Binary>::Instantiate());
  serializers.emplace("human",
                      cluster::event::Serializer<Format::Human>::Instantiate());
  serializers.emplace("broker_binv1",
                      new zeek::cluster::detail::BrokerBinV1_Serializer());
  serializers.emplace("broker_jsonv1",
                      new zeek::cluster::detail::BrokerJsonV1_Serializer());

  Timinig t_serialize;
  Timinig t_deserialize;

  for (auto &&[name, s] : serializers) {
    for (int i = 0; i < benchmark_iterations(); ++i) {
      zeek::byte_buffer buf;

      auto start = std::chrono::high_resolution_clock::now();
      s->SerializeEvent(buf, *event);
      auto end = std::chrono::high_resolution_clock::now();
      t_serialize[name].emplace_back(end - start);

      start = std::chrono::high_resolution_clock::now();
      s->UnserializeEvent(buf);
      end = std::chrono::high_resolution_clock::now();
      t_deserialize[name].emplace_back(end - start);
    }
  }

  summarize(suite->ToStdStringView(), t_serialize, t_deserialize);
}
} // namespace Zeek_more_serializers::detail::benchmark
