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

project(n64sym CXX ASM)

include_directories(include src)

add_executable(n64sym
src/n64sym_main.cpp
src/n64sym.cpp
src/signaturefile.cpp
src/crc32.cpp
src/threadpool.cpp
src/pathutil.cpp
src/elfutil.cpp
src/arutil.cpp
src/builtin_signatures_include.s)

add_executable(n64sig
src/n64sig_main.cpp
src/n64sig.cpp
src/elfutil.cpp
src/arutil.cpp
src/pathutil.cpp
src/crc32.cpp)



#find_package(Catch2 3 REQUIRED)
#
## These tests can use the Catch2-provided main
#add_executable(tests test.cpp)
#target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)
#
#include(CTest)
#include(Catch)
#catch_discover_tests(tests)
