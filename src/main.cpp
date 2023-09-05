//#include "../includes/capstone.h"
#include "elf/elf32.hpp"
#include "elf/elf64.hpp"
#include "elf/elf_abstract.hpp"
#include "./incs/capstone.h"
#include <iostream>
#include <string.h>
// https://www.capstone-engine.org/lang_c.html
#define COMMANDCAP 5

const char* commands[COMMANDCAP] = {
    "help", "?", 
    "sections", "dump",
    "quit"
};

#define HEXPRINT_AMOUNT 16
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define PURPLE "\033[0;35m"
#define BLUE "\033[0;34m"
#define CYAN "\033[0;36m"
#define WHITE "\033[0;37m"
#define DEFAULT_COLOR "\033[0m"
#define print_color(col, input, ...) \
    printf(col);\
    printf(input, __VA_ARGS__);\
    printf(DEFAULT_COLOR);
#define print_color_noargs(col, input) \
    printf(col);\
    printf(input);\
    printf(DEFAULT_COLOR);

const char* control_flows[] = {
    "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz",
    "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna",
    "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jng",
    "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz"
};

int main(int argc, char** argv) {
    std::cout << "Enter executable path: ";
    std::string path;
    std::cin >> path;
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) {
        printf("Couldn't open the file %s. Error: %s\n", path.c_str(), strerror(errno));
    }
    uint8_t type;
    fseek(file, 4, SEEK_SET);
    fread(&type, sizeof(uint8_t), 1, file);
    ElfBinary* binary;
    if (type == 1) binary = new Binary32(file);
    else if (type == 2) binary = new Binary64(file);
    // C++ inheritance is weird.
    binary->printHeader();
    binary->dumpSections();
    binary->dumpSectionBytes(".strtab");
    return 0;
}

// Capstone example
/*
    csh handle;
    cs_insn* instruction;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("capstone died L\n");
        return -1;
    }

    FILE* attempt = fopen(argv[1], "rt");
    ELF_File tryme(attempt);

    count = cs_disasm(handle, tryme.expose_code(), tryme.codeByteSize - 1, tryme.codeFileOffset, 0, &instruction);

    if (count > 0) {
        // only print first 10
        for (size_t i = 0; i < count; i++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", instruction[i].address, instruction[i].mnemonic,
					instruction[i].op_str);
        }
        cs_free(instruction, count);
    } else {
        printf("Could not disassemble, L\n");
        cs_free(instruction, count);
        return -1;
    }
    cs_close(&handle);
    fclose(attempt);
    */