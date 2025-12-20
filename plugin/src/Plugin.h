#pragma once

#include <zeek/plugin/Plugin.h>

namespace Zeek_more_serializers {

class Plugin : public zeek::plugin::Plugin {
protected:
  // Overridden from zeek::plugin::Plugin.
  zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace Zeek_more_serializers
  // namespace zeek::plugin
