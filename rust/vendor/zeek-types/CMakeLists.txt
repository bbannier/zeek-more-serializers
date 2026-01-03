include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_SHALLOW ON
    GIT_TAG v0.5.2
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(
    MANIFEST_PATH Cargo.toml
    CRATES zeek-types
    FEATURES corrosion
)
corrosion_add_cxxbridge(
    zeek_types_cxx
    CRATE zeek_types
    FILES lib.rs
)

target_sources(zeek_types_cxx PRIVATE src/interop.cc src/plugin.cc)

target_include_directories(zeek_types_cxx PRIVATE
    ${ZEEK_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_include_directories(zeek_types_cxx PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/.. # Allow including as `zeek-types/..`.
)
set_target_properties(zeek_types_cxx PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)
target_compile_definitions(zeek_types_cxx PUBLIC CORROSION_BUILD)
target_link_libraries(zeek_types_cxx PUBLIC zeek_types)
