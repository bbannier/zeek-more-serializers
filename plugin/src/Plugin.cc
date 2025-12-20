#include "Plugin.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>

#include "zeek/cluster/Component.h"
#include "zeek/cluster/Event.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Types.h"
#include "zeek/storage/Component.h"
#include "zeek/storage/Serializer.h"

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
}

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
