#ifndef E64_H
#define E64_H

#include "elf_abstract.hpp"
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <map>

/**
 * 32 bit Elf Header struct
 * 
 */
typedef struct {
    uint8_t ei_mag[4];
    uint8_t ei_class; // 1 - 32bit; 2 - 64bit
    uint8_t ei_data;
    uint8_t ei_version;
    uint8_t ei_osabi;
    uint8_t ei_abiversion;
    uint8_t ei_pad[7];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry; // entry point
    uint64_t e_phoff; // program header table ptr
    uint64_t e_shoff; // section header table ptr
    uint32_t e_flags;
    uint16_t e_ehsize;
    // ph entry size and # of entries
    uint16_t e_phentsize;
    uint16_t e_phnum;
    // sh entry size and # of entries
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ElfHeader64;

/**
 * 32 bit Program Header struct
 * 
 */
typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset; // offset of segment in file
    uint64_t p_vaddr; // va of seg in mem
    uint64_t p_paddr; // pa of seg in mem
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} ProgramHeader64;

/**
 * 32 bit Section Header struct
 * 
 */
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    // the important ones
    uint64_t sh_addr; // VA of section in mem
    uint64_t sh_offset; // offset of section into file
    uint64_t sh_size; // size of section
    // above
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} SectionHeader64;

// Note to self: C++ inheritance requires this to specify public
class Binary64 : public ElfBinary
{

private:
    ElfHeader64 elf_header;
    ProgramHeader64* program_header_table;
    SectionHeader64* section_header_table;

    uint32_t sections; // # of sections in executable
    FILE* handle;
    std::map<std::string, SectionHeader64*> section_map;
    std::map<SectionHeader64*, std::string> reverse_section_map;
public:
    Binary64(FILE* file);
    ~Binary64() {delete[] program_header_table; delete[] section_header_table; }
    void dumpSections() override;
    void printHeader() override;
    void dumpSectionBytes(std::string sectionName) override;
};

#endif