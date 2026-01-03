#pragma once

#include "rust/cxx.h"
#include "zeek/plugin/Plugin.h"
#include <memory>
#include <optional>
#include <string>

namespace support {

class PluginWrapper : zeek::plugin::Plugin {
public:
  static std::unique_ptr<PluginWrapper> make(rust::Str name,
                                             rust::Str description);

  PluginWrapper(std::string name_, std::string description_);

  void with_init_pre_execution(rust::Fn<void()> hook) {
    init_pre_execution = hook;
  }

  void InitPreExecution() override {
    if (init_pre_execution)
      (*init_pre_execution)();
  }

  zeek::plugin::Configuration Configure() override;

private:
  std::string name;
  std::string description;

  std::optional<rust::Fn<void()>> init_pre_execution;
};

} // namespace support
