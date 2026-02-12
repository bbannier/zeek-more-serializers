#pragma once

#include <zeek/Val.h>
#include <zeek/cluster/BifSupport.h>
#include <zeek/plugin/Plugin.h>

namespace Zeek_more_serializers {

class Plugin : public zeek::plugin::Plugin {
protected:
  zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

namespace detail::benchmark {
void bench_storage(zeek::StringVal *suite, const zeek::Val &val);
void bench_event(zeek::StringVal *suite, const zeek::ValPtr &topic,
                 zeek::ArgsSpan args);
} // namespace detail::benchmark

} // namespace Zeek_more_serializers
