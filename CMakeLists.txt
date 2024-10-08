cmake_minimum_required(VERSION 3.5)

# set because project uses new features
# and because using extensions causes problems with clang tidy
# as compiler settings json is generated using gnu++20 rather than std++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_CLANG_TIDY clang-tidy)
set(CMAKE_CXX_CLANG_TIDY_EXPORT_FIXES_DIR fixes)

project(objmatch CXX ASM)

include_directories(include src)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(YAMLCPP REQUIRED IMPORTED_TARGET yaml-cpp)

add_executable(
objmatch
src/objmatch_main.cpp
src/objmatch.cpp
)

add_executable(
objsig
src/objsig_main.cpp
src/objsig.cpp
)

target_link_libraries(objmatch PRIVATE PkgConfig::LIBELF PkgConfig::YAMLCPP)
target_link_libraries(objsig PRIVATE PkgConfig::LIBELF PkgConfig::YAMLCPP)

#find_package(Catch2 3 REQUIRED)
#
## These tests can use the Catch2-provided main
#add_executable(tests test.cpp)
#target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)
#
#include(CTest)
#include(Catch)
#catch_discover_tests(tests)
