//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/example.c -o src/object_test_src/out/example.o
//mips32-unknown-elf-gcc -G 0 src/object_test_src/out/example.o src/object_test_src/start.c -o src/object_test_src/out/start
//mips32-unknown-elf-objcopy src/object_test_src/out/start src/object_test_src/out/start.bin -O binary
#include "example.h"

void _start() {
    example(2);
}