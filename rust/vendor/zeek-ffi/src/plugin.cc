#include "plugin.h"

#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/module_util.h"
#include "zeek/plugin/Manager.h"
#include "zeek/plugin/Plugin.h"

#include <memory>
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

  zeek::plugin::Manager::RegisterBifFile(
      name.c_str(), [](::zeek::plugin::Plugin *plugin) {
        auto p = static_cast<PluginWrapper *>(plugin);
        assert(p);

        for (auto &&[name, fn] : p->bifs_to_register) {
          p->AddBifItem(name, zeek::plugin::BifItem::FUNCTION);
          p->bifs.push_back(std::make_unique<BuiltinFuncWrapper>(
              std::move(name), std::move(fn)));
        }
        p->bifs_to_register.clear();
      });

  return conf;
}

void PluginWrapper::add_bif_item_function(rust::Str name_, BifCallback fn) {
  auto name = std::string{name_.begin(), name_.end()};
  bifs_to_register[name] = fn;
}

BuiltinFuncWrapper::BuiltinFuncWrapper(std::string name_, BifCallback fn_)
    : Func(BUILTIN_FUNC), fn(std::move(fn_)) {
  name = std::move(name_);

  // FIXME(bbannier): This depends on the function already being declared,
  // e.g., in the plugin's `bif/__load__.zeek`. This should really happen
  // automatically.
  auto id =
      zeek::detail::lookup_ID(name.c_str(), zeek::detail::GLOBAL_MODULE_NAME);
  if (!id)
    zeek::reporter->FatalError("Missing definition of function '%s'",
                               name.c_str());
  assert(!id->HasVal());

  type = id->GetType<zeek::FuncType>();

  id->SetVal(zeek::make_intrusive<zeek::FuncVal>(
      zeek::IntrusivePtr{zeek::NewRef{}, this}));
  id->SetConst();
}

zeek::ValPtr BuiltinFuncWrapper::Invoke(zeek::Args *args,
                                        zeek::detail::Frame *parent) const {
  if (!args || !parent)
    return {};

  auto ret = fn(*parent, *args);
  return std::move(*ret);
}

void BuiltinFuncWrapper::Describe(zeek::ODesc *d) const {
  d->Add(name.c_str());
}

} // namespace support
