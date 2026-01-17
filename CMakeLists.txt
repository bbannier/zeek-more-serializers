# This file is maintained by zkg. Do not edit.
# Put required additional cmake functionality into plugin.cmake.
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(ZeekPluginmore_serializers VERSION 0.1.0 LANGUAGES CXX)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/plugin/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

add_subdirectory(rust)

# Our plugin source and scripts are in a subdirectory
set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}/plugin")

# Workaround to make header files in plugin sources available to BiFs.
include_directories("${BRO_PLUGIN_BASE}/src")

include(ZeekPlugin)

zeek_plugin_begin(Zeek more_serializers)

file(GLOB cc_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/*.cc")
foreach(file ${cc_files})
    zeek_plugin_cc(${file})
endforeach ()

file(GLOB bif_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/*.bif")
foreach(file ${bif_files})
    zeek_plugin_bif(${file})
endforeach ()

zeek_plugin_dist_files(README COPYING)

zeek_plugin_link_library(zeek_more_serializers_cxx)

zeek_plugin_end()
