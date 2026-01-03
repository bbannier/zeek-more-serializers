#include "plugin.h"
#include <utility>

namespace support {

std::unique_ptr<PluginWrapper> PluginWrapper::make(rust::Str name_,
                                                   rust::Str description_) {
  auto name = std::string{name_.begin(), name_.end()};
  auto description = std::string{description_.begin(), description_.end()};

  return std::make_unique<PluginWrapper>(std::move(name),
                                         std::move(description));
}

PluginWrapper::PluginWrapper(std::string name_, std::string description_)
    : name(std::move(name_)), description(std::move(description_)) {}

zeek::plugin::Configuration PluginWrapper::Configure() {
  zeek::plugin::Configuration conf;
  conf.name = name;
  conf.description = description;

  return conf;
}

} // namespace support
