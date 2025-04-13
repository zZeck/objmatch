#include "example_copy.h"

//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/example_copy.c -o src/object_test_src/out/example_copy.o
//mips32-unknown-elf-ar rcs src/object_test_src/out/libcopyexample.a src/object_test_src/out/example.o src/object_test_src/out/example_copy.o
//.text with reloc

// .data, initializing to 0 would be .bss
int number2 = 1;

// .rodata because const
const int number3 = 2;

// .text
int example2(int x) {
    return x + number0 + 4;
}
