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

#define HEXPRINT_AMOUNT 18

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
                    printf("\nWarning: instruction mode printing on sections that (likely) do not contain instructions\nWILL result " \
                            "in incorrect outputs, such as not printing enough instructions, interpreting wrong instructions, etc.\n\n");
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
                // also display as characters
                // some funny formatting stuff
                int j = 0;
                printf("0x%lX:\t", sectionInfo.image_offset);
                uint8_t charVersion[HEXPRINT_AMOUNT] = {0}; // 10 bc null term
                for (int i = 0; i < sectionInfo.sectionSize; i++) {
                    if (j == HEXPRINT_AMOUNT) {
                        // print ascii equivalent
                        printf("\t.");
                        for (char c : charVersion) {
                            printf("%c.", c);
                        }
                        printf("\n0x%lX:\t", sectionInfo.image_offset + i);
                        j = 0;
                    }
                    charVersion[i % HEXPRINT_AMOUNT] = data[i];
                    printf("%02X ", data[i]);
                    // if this is the last iteration then we want to print remaining and quit
                    if (i == sectionInfo.sectionSize - 1) {
                        for (int special = 1; special < HEXPRINT_AMOUNT - j; special++) {
                            printf("00 ");
                        }
                        printf("\t.");
                        for (char c : charVersion) {
                            printf("%c.", c);
                        }
                        break;
                    }
                    j++;
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