find_package(Zeek REQUIRED)

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_SHALLOW ON
    GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(
    MANIFEST_PATH Cargo.toml
    CRATES zeek-ffi
    LOCKED
    FEATURES corrosion
)
corrosion_add_cxxbridge(
    zeek_ffi_cxx
    CRATE zeek_ffi
    FILES lib.rs
)

target_sources(zeek_ffi_cxx PRIVATE src/interop.cc src/plugin.cc)

target_include_directories(zeek_ffi_cxx PRIVATE
    ${ZEEK_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_include_directories(zeek_ffi_cxx PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/.. # Allow including as `zeek-ffi/..`.
)
set_target_properties(zeek_ffi_cxx PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)
target_compile_definitions(zeek_ffi_cxx PUBLIC CORROSION_BUILD)
target_link_libraries(zeek_ffi_cxx PUBLIC zeek_ffi)
