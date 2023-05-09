#include "pe_file.hpp"
#include <string.h>

uint32_t PE_File::findSectionByName(const char* toFind) {
    for (int i = 0; i < number_of_sections; i++) {
        char name[8];
        memcpy(name, section_table[i].Name, 8);
        if (strcmp(toFind, name) == 0) {
            return i;
        }
    }
    printf("Could not find specified section %s!\n", toFind);
    return -1;
}

// print each import dll
void PE_File::printImports() {
    for (int i = 0; i < import_count; i++) {
        uint32_t nameAddress = generateFileOffset(import_table[i].Name);
        int importNameLen = 0;
        while (true) {
            char tmp;
            fseek(selectedFile, nameAddress + importNameLen, SEEK_SET);
            fread(&tmp, sizeof(char), 1, selectedFile);
            if (tmp == 0) {
                break;
            }
            importNameLen++;
        }
        char* namearr = new char[importNameLen];
        fseek(selectedFile, nameAddress, SEEK_SET);
        fread(namearr, importNameLen, 1, selectedFile);
        // print the DLL name
        printf("* \t%s\n", namearr);
    }
}