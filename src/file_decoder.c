#include "decode_helpers.h"
#include <stdlib.h>

// Helper
uint32_t rvaToOffset32(PEFile32* exec, DWORD va) {
    // find what section we are in
    int whatSection = -1;

    for (int i = 0; i < exec->PE_NTHeader.FileHeader.NumberOfSections; i++) {
        // bingo!
        if (va >= exec->PE_SectionHeaders[i].VirtualAddress && va < (exec->PE_SectionHeaders[i].VirtualAddress + exec->PE_SectionHeaders[i].Misc.VirtualSize)) {
            whatSection = i;
        }
    }

    if (whatSection == -1) {
        printf("Failed trying to get file offset from RVA = 0x%X\n", va);
        exit(-1);
    }

    return (va - exec->PE_SectionHeaders[whatSection].VirtualAddress) + exec->PE_SectionHeaders[whatSection].PointerToRawData;
}
// has to be copied bc nt/section headers different for 64... ugh
uint32_t rvaToOffset64(PEFile64* exec, DWORD va) {
    int whatSection = -1;
    for (int i = 0; i < exec->PE_NTHeader.FileHeader.NumberOfSections; i++) {
        // bingo!
        if (va >= exec->PE_SectionHeaders[i].VirtualAddress && va < (exec->PE_SectionHeaders[i].VirtualAddress + exec->PE_SectionHeaders[i].Misc.VirtualSize)) {
            whatSection = i;
        }
    }
    if (whatSection == -1) {
        printf("Failed trying to get file offset from RVA = 0x%X\n", va);
        exit(-1);
    }
    return (va - exec->PE_SectionHeaders[whatSection].VirtualAddress) + exec->PE_SectionHeaders[whatSection].PointerToRawData;
}

void destroy32(PEFile32* file) {
    free(file->PE_BaseRelocationTable);
    free(file->PE_ImportTable);
    free(file->PE_SectionHeaders);
}
void destroy64(PEFile64* file) {
    free(file->PE_BaseRelocationTable);
    free(file->PE_ImportTable);
    free(file->PE_SectionHeaders);
}

// Check magic number and others to verify if a PE file
uint8_t validateFile(FILE* exec) {
    dos_header temp;
    WORD filetype; // pe32 or pe32+

    // assumed exec will be opened already. do this in main.
    fseek(exec, 0, SEEK_SET); // begin at first byte of file
    // read in the (supposedly existing) DOS header
    fread(&temp, sizeof(dos_header), 1, exec);

    if (temp.e_magic != DOS_MAGIC) {
        printf("Not a PE file!\n");
        return NOT_PE;
    }
    long optionalHeaderOffset = (temp.e_lfanew + sizeof(DWORD) + sizeof(file_header));
    fseek(exec, optionalHeaderOffset, SEEK_SET);
    fread(&filetype, sizeof(WORD), 1, exec);

    if (filetype == pe32_magic) {
        return PE32;
    } else if (filetype == pe32plus_magic) {
        return PE64;
    } else {
        printf("File is either a ROM or some wacky funny type.\n");
        return NOT_PE;
    }
}

// Parse DOS headers
void parseDos32(PEFile32* exec) {
    fseek(exec->realFile, 0, SEEK_SET);
    fread(&(exec->PE_DosHeader), sizeof(dos_header), 1, exec->realFile);
}
void parseDos64(PEFile64* exec) {
    fseek(exec->realFile, 0, SEEK_SET);
    fread(&(exec->PE_DosHeader), sizeof(dos_header), 1, exec->realFile);
}

// Parse NT headers
void parseNT32(PEFile32* exec) {
    fseek(exec->realFile, exec->PE_DosHeader.e_lfanew, SEEK_SET);
    fread(&(exec->PE_NTHeader), sizeof(nt_header32), 1, exec->realFile);

    // bc im lazy
    data_directory* ddir = exec->PE_NTHeader.optional.DataDirectory;

    exec->exportDir = ddir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exec->importDir = ddir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    exec->resourceDir = ddir[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    exec->relocationDir = ddir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    exec->iatDir = ddir[IMAGE_DIRECTORY_ENTRY_IAT];
    exec->globalPointerDir = ddir[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
    exec->tlsDir = ddir[IMAGE_DIRECTORY_ENTRY_TLS];
    exec->loadConfigDir = ddir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    exec->boundImportDir = ddir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    exec->delayImportDir = ddir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    exec->comDescriptorDir = ddir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
}
void parseNT64(PEFile64* exec) {
    fseek(exec->realFile, exec->PE_DosHeader.e_lfanew, SEEK_SET);
    fread(&(exec->PE_NTHeader), sizeof(nt_header64), 1, exec->realFile);

    // bc im lazy
    data_directory* ddir = exec->PE_NTHeader.optional.DataDirectory;

    exec->exportDir = ddir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exec->importDir = ddir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    exec->resourceDir = ddir[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    exec->relocationDir = ddir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    exec->iatDir = ddir[IMAGE_DIRECTORY_ENTRY_IAT];
    exec->globalPointerDir = ddir[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
    exec->tlsDir = ddir[IMAGE_DIRECTORY_ENTRY_TLS];
    exec->loadConfigDir = ddir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    exec->boundImportDir = ddir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    exec->delayImportDir = ddir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    exec->comDescriptorDir = ddir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
}

// Parse section headers (ugly)
void parseSection32(PEFile32* exec) {
    exec->PE_SectionHeaders = (section_header*)malloc(sizeof(section_header) * exec->PE_NTHeader.FileHeader.NumberOfSections);

    // For each section header its address will be lfanew + sizeof(nt header) + index*section header size
    // because section table comes after NT
    for (int i = 0; i < exec->PE_NTHeader.FileHeader.NumberOfSections; i++) {
        int sectionHeaderOffset = (exec->PE_DosHeader.e_lfanew + sizeof(nt_header32) + (i * SECTION_HEADER_SIZE));
        fseek(exec->realFile, sectionHeaderOffset, SEEK_SET);
        fread(&(exec->PE_SectionHeaders[i]), SECTION_HEADER_SIZE, 1, exec->realFile);
    }
}
void parseSection64(PEFile64* exec) {
    exec->PE_SectionHeaders = (section_header*)malloc(sizeof(section_header) * exec->PE_NTHeader.FileHeader.NumberOfSections);
    for (int i = 0; i < exec->PE_NTHeader.FileHeader.NumberOfSections; i++) {
        int sectionHeaderOffset = (exec->PE_DosHeader.e_lfanew + sizeof(nt_header64) + (i * SECTION_HEADER_SIZE));
        fseek(exec->realFile, sectionHeaderOffset, SEEK_SET);
        fread(&(exec->PE_SectionHeaders[i]), SECTION_HEADER_SIZE, 1, exec->realFile);
    }
}

// Parse import directory
void parseImportDir32(PEFile32* exec) {
    DWORD dirAddr = rvaToOffset32(exec, exec->importDir.virtual_address);
    // need to find how many import descriptors we have in the import directory
    // if name and FirstThunk of an import descriptor are 0 then we are done. so loop to that.
    int importCount = 0;
    while (1) {
        import_descriptor copytemp;
        int offsetInDirectory = dirAddr + (importCount * sizeof(import_descriptor));
        fseek(exec->realFile, offsetInDirectory, SEEK_SET);
        fread(&copytemp, sizeof(import_descriptor), 1, exec->realFile);
        if (copytemp.Name == 0 && copytemp.FirstThunk == 0) {
            importCount--;
            exec->importDirectoryCount = importCount;
            exec->importDirectorySize = importCount * sizeof(import_descriptor);
            break;
        }
    }

    exec->PE_ImportTable = (import_descriptor*)malloc(sizeof(import_descriptor) * importCount);
    // copy everything over; need to rewind file pointer
    for (int i = 0; i < importCount; i++) {
        fseek(exec->realFile, (i * sizeof(import_descriptor)) + dirAddr, SEEK_SET);
        fread(&(exec->PE_ImportTable[i]), sizeof(import_descriptor), 1, exec->realFile);
    }
}
void parseImportDir64(PEFile64* exec) {
    DWORD dirAddr = rvaToOffset64(exec, exec->importDir.virtual_address);
    int importCount = 0;
    while (1) {
        import_descriptor copytemp;
        int offsetInDirectory = dirAddr + (importCount * sizeof(import_descriptor));
        fseek(exec->realFile, offsetInDirectory, SEEK_SET);
        fread(&copytemp, sizeof(import_descriptor), 1, exec->realFile);
        if (copytemp.Name == 0 && copytemp.FirstThunk == 0) {
            importCount--;
            exec->importDirectoryCount = importCount;
            exec->importDirectorySize = importCount * sizeof(import_descriptor);
            break;
        }
    }
    exec->PE_ImportTable = (import_descriptor*)malloc(sizeof(import_descriptor) * importCount);
    // copy everything over; need to rewind file pointer
    for (int i = 0; i < importCount; i++) {
        fseek(exec->realFile, (i * sizeof(import_descriptor)) + dirAddr, SEEK_SET);
        fread(&(exec->PE_ImportTable[i]), sizeof(import_descriptor), 1, exec->realFile);
    }
}

// Parse out relocation tables
// Really similar to import table; anything that has VA and size 0'd out marks the end
void parseRelocs32(PEFile32* exec) {
    DWORD relocAddr = rvaToOffset32(exec, exec->relocationDir.virtual_address);
    int relocCount = 0;
    int sizeCount = 0;
    while (1) {
        relocation_base temp;
        int offset = relocAddr + sizeCount;
        fseek(exec->realFile, offset, SEEK_SET);
        fread(&temp, sizeof(relocation_base), 1, exec->realFile);
        if (temp.SizeOfBlock == 0 && temp.VirtualAddress == 0) break;

        relocCount++;
        sizeCount += temp.SizeOfBlock;
    }
    exec->PE_BaseRelocationTable = (relocation_base*)malloc(sizeof(relocation_base) * relocCount);
    sizeCount = 0;
    // copy over into our array
    for (int i = 0; i < relocCount; i++) {
        int offset = relocAddr + sizeCount;
        fseek(exec->realFile, offset, SEEK_SET);
        fread(&(exec->PE_BaseRelocationTable[i]), sizeof(relocation_base), 1, exec->realFile);
        sizeCount += exec->PE_BaseRelocationTable[i].SizeOfBlock;
    }
}
void parseRelocs64(PEFile64* exec) {
    DWORD relocAddr = rvaToOffset64(exec, exec->relocationDir.virtual_address);
    int relocCount = 0;
    int sizeCount = 0;
    while (1) {
        relocation_base temp;
        int offset = relocAddr + sizeCount;
        fseek(exec->realFile, offset, SEEK_SET);
        fread(&temp, sizeof(relocation_base), 1, exec->realFile);
        if (temp.SizeOfBlock == 0 && temp.VirtualAddress == 0) break;

        relocCount++;
        sizeCount += temp.SizeOfBlock;
    }
    exec->PE_BaseRelocationTable = (relocation_base*)malloc(sizeof(relocation_base) * relocCount);
    sizeCount = 0;
    // copy over into our array
    for (int i = 0; i < relocCount; i++) {
        int offset = relocAddr + sizeCount;
        fseek(exec->realFile, offset, SEEK_SET);
        fread(&(exec->PE_BaseRelocationTable[i]), sizeof(relocation_base), 1, exec->realFile);
        sizeCount += exec->PE_BaseRelocationTable[i].SizeOfBlock;
    }
}
