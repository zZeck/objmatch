//mips32-unknown-elf-gcc -c -G 0 src/object_test_src/text_data_reloc.c
//.text with reloc
extern int number0;

int example(int x) {
    return x + number0 + 4;
}
