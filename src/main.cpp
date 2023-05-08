#include "elf/elf_file.hpp"

int main(int argc, char** argv) {
    FILE* attempt = fopen(argv[1], "rt");
    ELF_File hello(attempt);
    hello.basicInfo();
    hello.dumpSectionEntries();
    fclose(attempt);
}