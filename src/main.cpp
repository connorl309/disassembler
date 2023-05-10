//#include "../includes/capstone.h"
#include "elf/elf_file.hpp"
#include "./incs/capstone.h"

// https://www.capstone-engine.org/lang_c.html

const uint8_t CODE[] = {0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00};
// "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main(int argc, char** argv) {

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
    return 0;
}