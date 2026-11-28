#pragma once

#include "rust/cxx.h"
#include "zeek/Desc.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Obj.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"
#include "zeek/plugin/Plugin.h"
#include <memory>
#include <optional>
#include <string>

namespace support {

using BifCallback = rust::Fn<std::unique_ptr<::zeek::ValPtr>(
    zeek::detail::Frame &, const zeek::Args &args)>;

// We do not use `BuiltinFunc` since it is marked `final`.
struct BuiltinFuncWrapper : zeek::Func {
  BifCallback fn;
  BuiltinFuncWrapper(std::string name_, BifCallback fn_);

  virtual zeek::ValPtr
  Invoke(zeek::Args *args,
         zeek::detail::Frame *parent = nullptr) const override;

  bool IsPure() const override { return false; }

  void Describe(zeek::ODesc *d) const override;
};

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

  void add_bif_item_function(rust::Str name,
                             rust::Fn<std::unique_ptr<::zeek::ValPtr>(
                                 zeek::detail::Frame &, const zeek::Args &args)>
                                 fn);

private:
  std::string name;
  std::string description;

  std::optional<rust::Fn<void()>> init_pre_execution;

  std::map<std::string, BifCallback> bifs_to_register;
  // We store a pointer since `zeek::Func` can be neither copied nor moved.
  std::vector<std::unique_ptr<BuiltinFuncWrapper>> bifs;
};

} // namespace support
