#include "example.h"

//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/example.c -o src/object_test_src/out/example.o
//mips32-unknown-elf-ar rcs src/object_test_src/out/libexample.a src/object_test_src/out/example.o
//.text with reloc

// .data, initializing to 0 would be .bss
int number0 = 1;

// .rodata because const
const int number1 = 2;

// .text
int example(int x) {
    return x + number0 + 4;
}
