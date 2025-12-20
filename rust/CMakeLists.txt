string(REPLACE ":" ";" ZEEK_INCLUDE_DIR "${BRO_CONFIG_INCLUDE_DIR}")

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_SHALLOW ON
    GIT_TAG v0.5.2
)
FetchContent_MakeAvailable(Corrosion)

# Rust prefers to produce position-independent code, force it for the whole plugin.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(vendor/zeek-types)

corrosion_import_crate(
    MANIFEST_PATH Cargo.toml
    CRATES zeek-more-serializers
    FEATURES corrosion
)
corrosion_add_cxxbridge(
    zeek_more_serializers_cxx
    CRATE zeek_more_serializers
    FILES lib.rs
)

target_include_directories(zeek_more_serializers_cxx PUBLIC
    ${ZEEK_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
set_target_properties(zeek_more_serializers_cxx PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(zeek_more_serializers_cxx PUBLIC zeek_types_cxx)
