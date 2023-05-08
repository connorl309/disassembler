#include "elf_file.hpp"
#include <string.h>
#include <stdlib.h>

// Returns the section # that has the name of "name"
uint64_t ELF_File::findSectionByName(const char* name) {
    // Section name header table is a section .shstrtab
    // From section_name_index we can index into
    // SectionHeaderTable[name_index] and that is going to be the
    // section containing all the names
    // format:
    // \0 <string1> \0 <string2> ..... \0 ensures nullterm for all
    Section_Header_Entry32* sectionAs32 = static_cast<Section_Header_Entry32*>(SectionHeaderTable);
    Section_Header_Entry64* sectionAs64 = static_cast<Section_Header_Entry64*>(SectionHeaderTable);
    ELF_Header32* elfAs32 = static_cast<ELF_Header32*>(ElfHeader);
    ELF_Header64* elfAs64 = static_cast<ELF_Header64*>(ElfHeader);
    uint64_t nameSectionIndex = (is32) ? elfAs32->section_name_index : elfAs64->section_name_index;

    // Need to find .shstrtab section offset
    uint64_t offset = (is32) ? 
        sectionAs32[nameSectionIndex].sectionFileOffset :
        sectionAs64[nameSectionIndex].sectionFileOffset;
    uint64_t size = (is32) ?
        sectionAs32[nameSectionIndex].sectionFileSize :
        sectionAs64[nameSectionIndex].sectionFileSize;
    char* nameArray = new char[size];
    fseek(selectedFile, offset, SEEK_SET);
    fread(nameArray, sizeof(uint8_t), size, selectedFile);

    for (uint64_t i = 0; i < numberOfSectionHeaders; i++) {
        // need to crawl the table til we find null terminators.
        // first element always null term so we can skip.
        uint32_t strIndex = (is32) ? sectionAs32[i].sectionNameOffset : sectionAs64[i].sectionNameOffset; 
        if (strIndex == 0) continue; // i.e. undefined name
        // Found!
        if (strcmp(name, &(nameArray[strIndex])) == 0) {
            return i;
        }
    }
    delete[] nameArray;
    return -1;
}

void ELF_File::printSectionData(const char* name) {
    uint64_t sectionNumber = findSectionByName(name);
    if (sectionNumber == (uint64_t)-1) {
        printf("Specified section with name %s does not exist!\n", name);
    }

    ELF_Header32* elfAs32 = static_cast<ELF_Header32*>(ElfHeader);
    ELF_Header64* elfAs64 = static_cast<ELF_Header64*>(ElfHeader);
    Section_Header_Entry32* sectionAs32 = static_cast<Section_Header_Entry32*>(SectionHeaderTable);
    Section_Header_Entry64* sectionAs64 = static_cast<Section_Header_Entry64*>(SectionHeaderTable);
    
    uint64_t sectionSize = (is32) ? sectionAs32[sectionNumber].sectionFileSize : sectionAs64[sectionNumber].sectionFileSize;    
    uint8_t* sectionData = new uint8_t[sectionSize];
    uint64_t offsetIntoImage = (is32) ? sectionAs32[sectionNumber].sectionFileOffset : sectionAs64[sectionNumber].sectionFileOffset;
    fseek(selectedFile, offsetIntoImage, SEEK_SET);
    fread(sectionData, sizeof(uint8_t), sectionSize, selectedFile);

    for (int i = 0; i < sectionSize; i++) {
        printf("%.2X ", sectionData[i]);
    }

    delete[] sectionData;
}