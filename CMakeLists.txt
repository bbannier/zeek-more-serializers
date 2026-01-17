# This file is maintained by zkg. Do not edit.
# Put required additional cmake functionality into plugin.cmake.
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

execute_process(
  COMMAND zeek-config --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE
  OUTPUT_VARIABLE zeek_cmake_dir
  COMMAND_ERROR_IS_FATAL ANY)

list(PREPEND CMAKE_MODULE_PATH "${zeek_cmake_dir}")

project(ZeekPluginmore_serializers VERSION 0.1.0 LANGUAGES CXX)

configure_file("plugin/src/config.h.in" "config.h" @ONLY)

add_subdirectory(rust)

include(ZeekPlugin)

zeek_add_plugin(Zeek more_serializers
  SOURCES plugin/src/Plugin.cc
  BIFS plugin/src/more_serializers.bif
  DIST_FILES README COPYING
  DEPENDENCIES zeek_more_serializers_cxx
  INCLUDE_DIRS plugin/src)
