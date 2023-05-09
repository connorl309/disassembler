#include "pe_file.hpp"
#include <stdlib.h>

// Ctr/dtr
PE_File::PE_File(FILE* input) {
    selectedFile = input;

    parseDos();
    parseFileHeader();
    parseOptional();
    parseSections();
    parseImports();
}
PE_File::~PE_File() {
    delete[] section_table;
    delete[] import_table;
    delete[] relocation_table;

    if (is32) {
        delete static_cast<OPTIONAL_HEADER32*>(optional_header);
    } else {
        delete static_cast<OPTIONAL_HEADER64*>(optional_header);
    }
}

// File offset calculator
uint32_t PE_File::generateFileOffset(uint32_t rva) {
    // find section
    uint32_t index = -1;

    for (int i = 0; i < number_of_sections; i++) {
        if (rva >= section_table[i].VirtualAddress &&
            rva < (section_table[i].VirtualAddress + section_table[i].Misc.VirtualSize)) {
                index = i; break;
            }
    }
    if (index == -1) {
        printf("Error finding file offset from RVA %X, exiting", rva);
        exit(-1);
    }

    return (rva - section_table[index].VirtualAddress) + section_table[index].PointerToRawData;
}

// parse dos header
void PE_File::parseDos() {
    fseek(selectedFile, 0, SEEK_SET);
    fread(&dos_header, sizeof(dos_header), 1, selectedFile);
    if (dos_header.e_magic != 0x5A4D) {
        printf("Specified file does not have a valid PE magic number!\n");
        exit(-1);
    }
}

//
void PE_File::parseFileHeader() {
    fseek(selectedFile, dos_header.e_lfanew + 4, SEEK_SET);
    fread(&file_header, sizeof(FILE_HEADER), 1, selectedFile);
    number_of_sections = file_header.NumberOfSections;
    section_table = new SECTION_HEADER[number_of_sections];
    size_of_optional = file_header.SizeOfOptionalHeader;
}

// parse optional header
void PE_File::parseOptional() {
    fseek(selectedFile, dos_header.e_lfanew + 4 + sizeof(FILE_HEADER), SEEK_SET);
    uint16_t typeBuffer;
    fread(&typeBuffer, sizeof(uint16_t), 1, selectedFile);
    if (typeBuffer == 0x10b) { // 32 bit
        is32 = true;
        optional_header = new OPTIONAL_HEADER32;
    } else if (typeBuffer == 0x20b) {
        is32 = false;
        optional_header = new OPTIONAL_HEADER64;
    }
    // just in case
    fseek(selectedFile, dos_header.e_lfanew + 4 + sizeof(FILE_HEADER), SEEK_SET);
    fread(optional_header, size_of_optional, 1, selectedFile);
}

// parse section headers
void PE_File::parseSections() {
    fseek(selectedFile, dos_header.e_lfanew + 4 + sizeof(FILE_HEADER) + size_of_optional, SEEK_SET);
    fread(section_table, sizeof(SECTION_HEADER), number_of_sections, selectedFile);
}

// parse import dir
void PE_File::parseImports() {
    // import directory is in optional
    OPTIONAL_HEADER32* opt32 = static_cast<OPTIONAL_HEADER32*>(optional_header);
    OPTIONAL_HEADER64* opt64 = static_cast<OPTIONAL_HEADER64*>(optional_header);
    uint32_t va = (is32) ? opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
                         : opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    uint32_t fileOffset = generateFileOffset(va);

    int count = 0;
    // get # of imports
    while (true) {
        IMPORT_DESCRIPTOR temp;
        int offset = (count * sizeof(IMPORT_DESCRIPTOR)) + fileOffset;
        fseek(selectedFile, offset, SEEK_SET);
        fread(&temp, sizeof(IMPORT_DESCRIPTOR), 1, selectedFile);
        if (temp.Name == 0 && temp.FirstThunk == 0) {
            count -= 1;
            import_count = count;
            import_size = (import_count * sizeof(IMPORT_DESCRIPTOR));
            break;
        }
        count++;
    }
    import_table = new IMPORT_DESCRIPTOR[count];
    fseek(selectedFile, fileOffset, SEEK_SET);
    fread(import_table, sizeof(IMPORT_DESCRIPTOR), count, selectedFile);
}