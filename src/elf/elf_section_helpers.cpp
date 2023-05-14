#include "elf_file.hpp"
#include <string.h>
#include <stdlib.h>

// Returns the section # that has the name of "name"
uint64_t ELF_File::findSectionByName(const char* name, bool cliHelp) {
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
    char* nameArray = new char[size + 1];
    fseek(selectedFile, offset, SEEK_SET);
    fread(nameArray, sizeof(uint8_t), size, selectedFile);

    for (uint64_t i = 0; i < numberOfSectionHeaders; i++) {
        // need to crawl the table til we find null terminators.
        // first element always null term so we can skip.
        uint32_t strIndex = (is32) ? sectionAs32[i].sectionNameOffset : sectionAs64[i].sectionNameOffset; 
        if (strIndex == 0) continue; // i.e. undefined name
        // Found!
        if (cliHelp == false) {
            if (strcmp(name, &(nameArray[strIndex])) == 0) {
                return i;
            }
        } else { // for the CLI - print every section's name, file offset, and size
            printf("Section [%ld]:\t'%s'\n*\tFile Offset: 0x%lX\n*\tSection size (in bytes): 0x%lX\n\n", i, &nameArray[strIndex], 
                (is32) ? sectionAs32[i].sectionFileOffset : sectionAs64[i].sectionFileOffset,
                (is32) ? sectionAs32[i].sectionFileSize : sectionAs64[i].sectionFileSize);
        }
    }
    delete[] nameArray;
    return -1;
}

// Gives a return struct containing file offset and section size
// for a section of name "name"
returnSection ELF_File::getSectionData(const char* name) {
    uint64_t sectionNumber = findSectionByName(name, false);
    if (sectionNumber == (uint64_t)-1) {
        printf("Specified section with name %s does not exist!\n", name);
    }

    ELF_Header32* elfAs32 = static_cast<ELF_Header32*>(ElfHeader);
    ELF_Header64* elfAs64 = static_cast<ELF_Header64*>(ElfHeader);
    Section_Header_Entry32* sectionAs32 = static_cast<Section_Header_Entry32*>(SectionHeaderTable);
    Section_Header_Entry64* sectionAs64 = static_cast<Section_Header_Entry64*>(SectionHeaderTable);
    
    uint64_t sectionSize = (is32) ? sectionAs32[sectionNumber].sectionFileSize : sectionAs64[sectionNumber].sectionFileSize;
    uint64_t offsetIntoImage = (is32) ? sectionAs32[sectionNumber].sectionFileOffset : sectionAs64[sectionNumber].sectionFileOffset;

    returnSection toReturn = {offsetIntoImage, sectionSize};
    return toReturn;
}

// Mostly internal
returnSection ELF_File::getSectionDataIndex(uint64_t index) {
    ELF_Header32* elfAs32 = static_cast<ELF_Header32*>(ElfHeader);
    ELF_Header64* elfAs64 = static_cast<ELF_Header64*>(ElfHeader);
    Section_Header_Entry32* sectionAs32 = static_cast<Section_Header_Entry32*>(SectionHeaderTable);
    Section_Header_Entry64* sectionAs64 = static_cast<Section_Header_Entry64*>(SectionHeaderTable);
    if (is32) {
        if (index >= elfAs32->section_header_count) {
            printf("Section index out of bounds!\n");
            return {UINT64_MAX, UINT64_MAX};
        }
    } else {
        if (index >= elfAs64->section_header_count) {
            printf("Section index out of bounds!\n");
            return {UINT64_MAX, UINT64_MAX};
        }
    }

    uint64_t sectionSize = (is32) ? sectionAs32[index].sectionFileSize : sectionAs64[index].sectionFileSize;
    uint64_t offsetIntoImage = (is32) ? sectionAs32[index].sectionFileOffset : sectionAs64[index].sectionFileOffset;
    returnSection toReturn = {offsetIntoImage, sectionSize};
    return toReturn;
}

// Returns a pointer to an array containing specified section data
// Will need to revamp as allocating megabytes of stuff is. Not smart.
uint8_t* ELF_File::sectionArray(returnSection abc) {
    uint8_t* toReturn = new uint8_t[abc.sectionSize];
    fseek(selectedFile, abc.image_offset, SEEK_SET);
    fread(toReturn, sizeof(uint8_t), abc.sectionSize, selectedFile);
    return toReturn;
}

// Symbol table helper - return table entry data
char* ELF_File::symbolTableGrab(uint64_t address) {
    Symbol_Table_Entry32* sym32 = static_cast<Symbol_Table_Entry32*>(SymbolTable);
    Symbol_Table_Entry64* sym64 = static_cast<Symbol_Table_Entry64*>(SymbolTable);

    returnSection strtab = getSectionData(".strtab");
    char* symname = new char[100];
    memset(symname, '\0', 100);
    
    if (is32) {
        for (int i = 0; i < symbolTableEntries; i++) {
            //fseek(selectedFile, strtab.image_offset + sym32[i].st_name, SEEK_SET);
            if (sym32[i].st_value == address) {
                fseek(selectedFile, strtab.image_offset + sym32[i].st_name, SEEK_SET);
                fread(symname, sizeof(char), 100, selectedFile);
                break;
            }
        }
    } else {
        for (int i = 0; i < symbolTableEntries; i++) {
            //fseek(selectedFile, strtab.image_offset + sym64[i].st_name, SEEK_SET);
            if (sym64[i].st_value == address) {
                fseek(selectedFile, strtab.image_offset + sym64[i].st_name, SEEK_SET);
                fread(symname, sizeof(char), 100, selectedFile);
                break;
            }
        }
    }

    return symname;
}   
