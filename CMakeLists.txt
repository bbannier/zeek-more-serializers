# This file is maintained by zkg. Do not edit.
# Put required additional cmake functionality into plugin.cmake.
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(ZeekPluginmore_serializers VERSION 0.1.0 LANGUAGES CXX)

configure_file("plugin/src/config.h.in" "config.h" @ONLY)

add_subdirectory(rust)

include(ZeekPlugin)

zeek_plugin_begin(Zeek more_serializers)

zeek_plugin_cc("plugin/src/Plugin.cc")
zeek_plugin_bif("plugin/src/more_serializers.bif")
zeek_plugin_dist_files(README COPYING)
zeek_plugin_link_library(zeek_more_serializers_cxx)

zeek_plugin_end()

target_include_directories(Zeek_more_serializers PUBLIC "plugin/src")
