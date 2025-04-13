//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/example.c -o src/object_test_src/out/example.o
//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/example_copy.c -o src/object_test_src/out/example_copy.o
//mips32-unknown-elf-gcc -G 0 src/object_test_src/out/example.o src/object_test_src/out/example_copy.o src/object_test_src/start_copy.c -o src/object_test_src/out/start_copy
//mips32-unknown-elf-objcopy src/object_test_src/out/start_copy src/object_test_src/out/start_copy.bin -O binary
//When patterns are found multiple times in the same binary, this needs special handling
//This file makes a binary with 2 identical functions
#include "example.h"
#include "example_copy.h"

void _start() {
    example(2);
    example2(2);
}
