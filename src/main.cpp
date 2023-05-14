//#include "../includes/capstone.h"
#include "elf/elf_file.hpp"
#include "./incs/capstone.h"
#include <string.h>

// https://www.capstone-engine.org/lang_c.html
#define COMMANDCAP 5

const char* commands[COMMANDCAP] = {
    "help", "?", 
    "sections", "dump",
    "quit"
};

int main(int argc, char** argv) {

    // may explode. handle later
    ELF_File executable(fopen(argv[1], "rt"));

    printf("\nThe Disassembler\n");
    printf("Type 'help' or '?' for a list of commands.\n> ");

    char buffer[100];
    scanf("%s", buffer);
    printf("%s\n", buffer);

    while (strcmp(buffer, "quit")) {
        if (!strcmp(buffer, "help") || !strcmp(buffer, "?")) {
            printf("Commands: ");
            for (int i = 0; i < COMMANDCAP; i++) {
                printf("|'%s'", commands[i]);
            }
            printf("|\n");
        }
        if (!strcmp(buffer, "sections")) {
            executable.findSectionByName("", true);
        }

        // dump section data
        if (!strcmp(buffer, "dump")) {
            printf("Please enter a section index to dump (see 'sections' for more): ");
            int num;
            scanf("%d", &num);
            returnSection sectionInfo = executable.getSectionDataIndex(num);
            uint8_t* data = executable.sectionArray(sectionInfo);
            printf("As instructions (i), or hex view (h)? ");
            char answer[3];
            scanf("%s", answer);
            if (!strcmp(answer, "i")) {  // instruction mode
                csh handle;
                cs_insn* instruction;
                size_t count;

                if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                    printf("capstone died L\n");
                    return -1;
                }
                // dewit!
                count = cs_disasm(handle, data, sectionInfo.sectionSize, sectionInfo.image_offset, 0, &instruction);
                if (count > 0) {
                    for (size_t i = 0; i < count; i++) {
                        printf("0x%"PRIx64":\t%s\t\t%s\n", instruction[i].address, instruction[i].mnemonic,
                                instruction[i].op_str);
                        // split any probable function blocks apart
                        if (!strcmp(instruction[i].mnemonic, "endbr64") ||
                            !strcmp(instruction[i].mnemonic, "endbr32") ||
                            !strcmp(instruction[i].mnemonic, "ret")) {
                                printf("\n");
                            }
                    }
                    cs_free(instruction, count);
                } else {
                    printf("Could not disassemble, L\n");
                    cs_free(instruction, count);
                    return -1;
                }
                cs_close(&handle);
            } else { // hex mode
                for (int i = 0; i < sectionInfo.sectionSize; i++) {
                    printf("%02X ", data[i]);
                }
                printf("\n");
            }
            delete[] data; // generated inside sectionArray() call
        }
        if (!strcmp(buffer, "quit")) {
            break;
        }
        printf("> ");
        scanf("%s", buffer);
    }
    printf("Bye bye.\n");
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