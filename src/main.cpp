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
                // do the disassembly

// TODO: see if we can convert "static" addresses into their symbol equivalents
// from symtable.
                count = cs_disasm(handle, data, sectionInfo.sectionSize, sectionInfo.image_offset, 0, &instruction);
                if (count > 0) {
                    printf("\nWarning: instruction mode printing on sections that (likely) do not contain instructions\nWILL result " \
                            "in incorrect outputs, such as not printing enough instructions, interpreting wrong instructions, etc.\n\n");
                    for (size_t i = 0; i < count; i++) {
                        printf("0x%"PRIx64":\t%s\t\t%s", instruction[i].address, instruction[i].mnemonic,
                                instruction[i].op_str);
                                
                        // todo: fix this its fucked
                        if (!strcmp("jmp", instruction[i].mnemonic) || !strcmp(control_flows[ 0 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 1 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 2 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 3 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 4 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 5 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 6 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 7 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 8 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 9 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 10 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 11 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 12 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 13 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 14 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 15 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 16 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 17 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 18 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 19 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 20 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 21 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 22 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 23 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 24 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 25 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 26 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 27 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 28 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 29 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 30 ], instruction[i].mnemonic) ||
                            !strcmp(control_flows[ 31 ], instruction[i].mnemonic) || !strcmp("call", instruction[i].mnemonic)) {
                            uint64_t interpreted_address = (uint64_t)strtol(instruction[i].op_str, NULL, 0);
                            char* nameptr = executable.symbolTableGrab(interpreted_address);
                            if (strlen(nameptr) > 0) {
                                print_color(GREEN, "\t ; Symbol '%s'", nameptr);
                            } else {
                                print_color_noargs(BLUE, "\t ; local address");
                            }
                            delete[] nameptr;
                        }  
                        // split any probable function blocks apart
                        if (!strcmp(instruction[i].mnemonic, "endbr64") ||
                            !strcmp(instruction[i].mnemonic, "endbr32") ||
                            !strcmp(instruction[i].mnemonic, "ret")) {
                                printf("\n");
                            }
                        printf("\n");
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
                int color_count = 0;
                printf("0x%lX:\t", sectionInfo.image_offset);
                uint8_t charVersion[HEXPRINT_AMOUNT] = {0}; // 10 bc null term
                char* list[] = {
                        WHITE, BLUE
                    };
                for (int i = 0; i < sectionInfo.sectionSize; i++) {
                    if (j == HEXPRINT_AMOUNT) {
                        // print ascii equivalent
                        printf("\t.");
                        for (char c : charVersion) {
                            print_color(list[color_count % 2], "%c.", c);
                        }
                        printf("\n0x%lX:\t", sectionInfo.image_offset + i);
                        j = 0;
                    }
                    charVersion[i % HEXPRINT_AMOUNT] = data[i];
                    if (data[i] == 0) {
                        print_color("\033[0;33m", "%02X ", data[i]);
                        color_count++;
                    } else {
                        print_color(list[color_count % 2], "%02X ", data[i]);
                    }
                    // if this is the last iteration then we want to print remaining and quit
                    if (i == sectionInfo.sectionSize - 1) {
                        for (int special = 1; special < HEXPRINT_AMOUNT - j; special++) {
                            printf("00 ");
                        }
                        printf("\t.");
                        for (char c : charVersion) {
                            print_color(list[color_count % 2], "%c.", c);
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