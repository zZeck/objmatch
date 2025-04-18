cmake_minimum_required(VERSION 3.5)

# set because project uses new features
# and because using extensions causes problems with clang tidy
# as compiler settings json is generated using gnu++20 rather than std++20
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Using ccache")
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()


#this should be limited to clang C++? or does it even matter really
#add_compile_options(-ftime-trace -ftime-report -Xclang -fno-pch-timestamp)
#add_compile_options(-O0 -fno-inline -ggdb3 -Xclang -fno-pch-timestamp -fno-omit-frame-pointer)
add_compile_options(-O0 -g -march=native)

option(ENABLE_CLANG_TIDY "Enable clang-tidy code analysis" OFF)
if(ENABLE_CLANG_TIDY)
find_program(CLANG_TIDY NAMES clang-tidy)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY}")
else()
    message(WARNING "clang-tidy not found, code analysis will be disabled.")
endif()
endif()

#clang tidy running every build makes them slow
#set(CMAKE_CXX_CLANG_TIDY clang-tidy)
set(CMAKE_CXX_CLANG_TIDY_EXPORT_FIXES_DIR fixes)

project(objmatch CXX ASM)

include_directories(include src)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)

find_package(ryml REQUIRED)
find_package(Crc32c REQUIRED)

add_executable(
objmatch
src/objmatch_main.cpp
src/objmatch.cpp
src/signature.cpp
src/splat_out.cpp
)

add_executable(
objsig
src/objsig_main.cpp
src/objsig.cpp
src/signature.cpp
)

add_executable(
matcher
src/matcher_main.cpp
src/matcher.cpp
src/splat_out.cpp
src/section_pattern.cpp
src/file_path_yaml.cpp
src/files_to_mapping.cpp
)

add_executable(
yamltrip
src/yamltrip.cpp
src/signature.cpp
)

target_link_libraries(matcher PRIVATE PkgConfig::LIBELF ryml::ryml Crc32c::crc32c)
target_link_libraries(objmatch PRIVATE PkgConfig::LIBELF ryml::ryml Crc32c::crc32c)
target_link_libraries(objsig PRIVATE PkgConfig::LIBELF ryml::ryml Crc32c::crc32c)
target_link_libraries(yamltrip PRIVATE ryml::ryml)

target_precompile_headers(yamltrip PUBLIC
<algorithm>
<filesystem>
<fstream>
<span>
<vector>
)

find_package(Catch2 3 REQUIRED)

# These tests can use the Catch2-provided main
add_executable(sig_yaml_tests src/yaml_test.cpp src/signature.cpp src/section_pattern.cpp)
add_executable(matcher_tests src/matcher_test.cpp src/matcher.cpp src/splat_out.cpp src/signature.cpp src/section_pattern.cpp)
add_executable(file_mapping_tests src/file_mapping_test.cpp src/files_to_mapping.cpp)
target_link_libraries(sig_yaml_tests PRIVATE Catch2::Catch2WithMain ryml::ryml)
target_link_libraries(matcher_tests PRIVATE PkgConfig::LIBELF Catch2::Catch2WithMain ryml::ryml Crc32c::crc32c)
target_link_libraries(file_mapping_tests PRIVATE Catch2::Catch2WithMain)


include(CTest)
include(Catch)
catch_discover_tests(sig_yaml_tests)
catch_discover_tests(matcher_tests WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
catch_discover_tests(file_mapping_tests WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
