//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/text_data_reloc.c
//mips32-unknown-elf-ar rcs libexample.a src/object_test_src/out/example.o
//.text with reloc
extern int number0;

int example(int x) {
    return x + number0 + 4;
}
