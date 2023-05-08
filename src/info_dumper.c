#include "decode_helpers.h"
#include "file_structs.h"
#include <string.h>

// Info and others
void dumpSections32(PEFile32* exec) {
    printf("Sections:\n");
    for (int i = 0; i < exec->PE_NTHeader.FileHeader.NumberOfSections; i++) {
        printf("* .%8s:", exec->PE_SectionHeaders[i].SectionName);
        printf("\t\tVA: 0x%X\n", exec->PE_SectionHeaders[i].VirtualAddress);
        printf("\t\tSize: 0x%X\n", exec->PE_SectionHeaders[i].Misc.VirtualSize);
        printf("\t\tPointer to data: 0x%X\n", exec->PE_SectionHeaders[i].PointerToRawData);
        printf("\t\tSize of data: 0x%X\n", exec->PE_SectionHeaders[i].SizeOfRawData);
    }
}
void dumpSections64(PEFile64* exec) {
    printf("Sections:\n");
    for (int i = 0; i < exec->PE_NTHeader.FileHeader.NumberOfSections; i++) {
        printf("* .%8s:", exec->PE_SectionHeaders[i].SectionName);
        printf("\t\tVA: 0x%X\n", exec->PE_SectionHeaders[i].VirtualAddress);
        printf("\t\tSize: 0x%X\n", exec->PE_SectionHeaders[i].Misc.VirtualSize);
        printf("\t\tPointer to data: 0x%X\n", exec->PE_SectionHeaders[i].PointerToRawData);
        printf("\t\tSize of data: 0x%X\n", exec->PE_SectionHeaders[i].SizeOfRawData);
    }
}

// For now just list the .dll's all being used.
// Can figure out every symbol used in the DLLs later.
void dumpImports32(PEFile32* exec) {
    printf("Imports:\n");
    for (int i = 0; i < exec->importDirectoryCount; i++) {
        char nameBuffer[100];
        DWORD nameAddress = rvaToOffset32(exec, exec->PE_ImportTable[i].Name);
        strcpy(nameBuffer, nameAddress);
        printf("* %s\n", nameBuffer);
    }
}
void dumpImports64(PEFile64* exec) {
    printf("Imports:\n");
    for (int i = 0; i < exec->importDirectoryCount; i++) {
        char nameBuffer[100];
        DWORD nameAddress = rvaToOffset64(exec, exec->PE_ImportTable[i].Name);
        strcpy(nameBuffer, nameAddress);
        printf("* %s\n", nameBuffer);
    }
}