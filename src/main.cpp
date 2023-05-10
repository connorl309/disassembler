#include "elf/elf_file.hpp"

int main(int argc, char** argv) {
    FILE* attempt = fopen(argv[1], "rt");
    ELF_File tryme(attempt);
    
    fclose(attempt);
    return 0;
}