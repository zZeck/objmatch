#include "example.h"

//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/example.c -o src/object_test_src/out/example.o
//mips32-unknown-elf-ar rcs libexample.a src/object_test_src/out/example.o
//.text with reloc

int number0 = 0;

int example(int x) {
    return x + number0 + 4;
}
