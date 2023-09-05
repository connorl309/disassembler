#ifndef E32_H
#define E32_H

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
    uint32_t e_entry; // entry point
    uint32_t e_phoff; // program header table ptr
    uint32_t e_shoff; // section header table ptr
    uint32_t e_flags;
    uint16_t e_ehsize;
    // ph entry size and # of entries
    uint16_t e_phentsize;
    uint16_t e_phnum;
    // sh entry size and # of entries
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ElfHeader32;

/**
 * 32 bit Program Header struct
 * 
 */
typedef struct {
    uint32_t p_type;
    uint32_t p_offset; // offset of segment in file
    uint32_t p_vaddr; // va of seg in mem
    uint32_t p_paddr; // pa of seg in mem
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} ProgramHeader32;

/**
 * 32 bit Section Header struct
 * 
 */
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    // the important ones
    uint32_t sh_addr; // VA of section in mem
    uint32_t sh_offset; // offset of section into file
    uint32_t sh_size; // size of section
    // above
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} SectionHeader32;

// Note to self: C++ inheritance requires this to specify public
class Binary32 : public ElfBinary
{

private:
    ElfHeader32 elf_header;
    ProgramHeader32* program_header_table;
    SectionHeader32* section_header_table;

    uint32_t sections; // # of sections in executable
    FILE* handle;
    std::map<std::string, SectionHeader32*> section_map;
    std::map<SectionHeader32*, std::string> reverse_section_map;
public:
    Binary32(FILE* file);
    ~Binary32() {delete[] program_header_table; delete[] section_header_table; }
    void dumpSections() override;
    void printHeader() override;
    void dumpSectionBytes(std::string sectionName) override;
    void cleanup() override;
};

#endif