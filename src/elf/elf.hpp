#ifndef ELF_H
#define ELF_H

/**
 * Header file for the representation of an ELF file and parser.
 * Some funny data upcasting to bypass requiring  
 */

#include <stdint.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <vector>

typedef enum {
    IS_32BIT = 0x1,
    IS_64BIT = 0x2,
} bit_type;

typedef struct {
    uint32_t type;
    uint32_t seg_offset;
    uint32_t vaddr; // va
    uint32_t paddr; // pa
    uint32_t seg_size_file; // in bytes
    uint32_t seg_size_mem; // in bytes
    uint32_t flags;
    uint32_t alignment; // 0, 1, or a power of 2; vaddr = seg_offset % align
} ph32;
typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t seg_offset;
    uint64_t vaddr; // va
    uint64_t paddr; // pa
    uint64_t seg_size_file; // in bytes
    uint64_t seg_size_mem; // in bytes
    uint64_t alignment; // 0, 1, or a power of 2; vaddr = seg_offset % align
} ph64;
// Program header entry
class ProgramHeader
{
private:
    
    enum {
        PF_X = 0x1, // executable
        PF_W = 0x2, // writeable
        PF_R = 0x3, // readable
    };
    uint32_t type;
    uint32_t flags;
    uint64_t seg_offset;
    uint64_t vaddr; // va
    uint64_t paddr; // pa
    uint64_t seg_size_file; // in bytes
    uint64_t seg_size_mem; // in bytes
    uint64_t alignment; // 0, 1, or a power of 2; vaddr = seg_offset % align

public:
    ProgramHeader(bit_type t, uint64_t file_offset, FILE* file);
};

// same for sh
typedef struct {
    uint32_t name_idx;
    std::string section_name; // custom, not part of a section header
    uint32_t type;
    uint32_t flags;
    uint32_t vaddr; // va of section in mem
    uint32_t file_offset;
    uint32_t section_size;
    uint32_t sh_link; // ??
    uint32_t sh_info; // ??
    uint32_t align; // must be power of 2
    uint32_t entry_size;
} sh32;
typedef struct {
    uint32_t name_idx;
    std::string section_name; // custom, not part of a section header
    uint32_t type;
    uint64_t flags;
    uint64_t vaddr; // va of section in mem
    uint64_t file_offset;
    uint64_t section_size;
    uint32_t sh_link; // ??
    uint32_t sh_info; // ??
    uint64_t align; // must be power of 2
    uint64_t entry_size;
} sh64;
// Section header entry (we care about this more tbh)
class SectionHeader
{
    // For flags
    enum {
        SHF_WRITE = 0x1,
        SHF_ALLOC = 0x2,
        SHF_EXECINSTR = 0x4,
        SHF_MERGE = 0x10,
        SHF_STRINGS = 0x20,
        SHF_INFO_LINK = 0x40,
        SHF_LINK_ORDER = 0x80,
        SHF_OS_NONCONFORMING = 0x100,
        SHF_GROUP = 0x200,
        SHF_TLS = 0x400,
        SHF_MASKOS = 0x0FF00000,
        SHF_MASKPROC = 0xF0000000,
        SHF_ORDERED = 0x4000000,
        SHF_EXCLUDE = 0x8000000
    };
private:
    uint32_t name_idx;
    std::string section_name; // custom, not part of a section header
    uint32_t type;
    uint64_t flags;
    uint64_t vaddr; // va of section in mem
    uint64_t file_offset;
    uint64_t section_size;
    uint32_t sh_link; // ??
    uint32_t sh_info; // ??
    uint64_t align; // must be power of 2
    uint64_t entry_size;

public:
    SectionHeader(bit_type t, uint64_t file_offset, FILE* file);
    void setname(std::string name);
    std::string getname();
    inline uint32_t get_name_index() { return name_idx; }
    inline uint64_t get_offset() { return file_offset; }
    inline uint64_t get_size() { return section_size; }
};

// and same for the binary itself (elf header)
typedef struct {
    uint32_t magic_number;
    uint8_t bit_size;
    uint8_t endian;
    uint8_t version;
    uint8_t abi;
    uint8_t abi_ver;
    uint8_t padding[7];
    uint16_t binary_type; 
    uint16_t isa;
    uint32_t elf_ver;
    uint32_t entrypoint; // either 4 or 8 byte, but we'll upcast to 8 byte regardless.
    uint32_t ph_offset; // program header table offset
    uint32_t sh_offset; // section header table offset
    uint32_t flags; // ???
    uint16_t entry_header_size;
    uint16_t ph_entry_size;
    uint16_t ph_num;
    uint16_t sh_entry_size;
    uint16_t sh_num;
    uint16_t sh_name_index;
} eh32;
typedef struct {
    uint32_t magic_number;
    uint8_t bit_size;
    uint8_t endian;
    uint8_t version;
    uint8_t abi;
    uint8_t abi_ver;
    uint8_t padding[7];
    uint16_t binary_type; 
    uint16_t isa;
    uint32_t elf_ver;
    uint64_t entrypoint; // either 4 or 8 byte, but we'll upcast to 8 byte regardless.
    uint64_t ph_offset; // program header table offset
    uint64_t sh_offset; // section header table offset
    uint32_t flags; // ???
    uint16_t entry_header_size;
    uint16_t ph_entry_size;
    uint16_t ph_num;
    uint16_t sh_entry_size;
    uint16_t sh_num;
    uint16_t sh_name_index;
} eh64;

/**
 * Binary file class
 * 
 * Contains relevant variables, structs, etc
 * 
 */
class Binary
{
// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
private:

    uint32_t magic_number;
    uint8_t bit_size;
    uint8_t endian;
    uint8_t version;
    uint8_t abi;
    uint8_t abi_ver;
    uint8_t padding[7];
    uint16_t binary_type; 
    uint16_t isa;
    uint32_t elf_ver;
    uint64_t entrypoint; // either 4 or 8 byte, but we'll upcast to 8 byte regardless.
    uint64_t ph_offset; // program header table offset
    uint64_t sh_offset; // section header table offset
    uint32_t flags; // ???
    uint16_t entry_header_size;
    uint16_t ph_entry_size;
    uint16_t ph_num;
    uint16_t sh_entry_size;
    uint16_t sh_num;
    uint16_t sh_name_index;

    std::vector<ProgramHeader> pht;
    std::vector<SectionHeader> sht;

    FILE* file_handle;    

    char* strtab;

public:
    Binary(std::string filepath);
    ~Binary();
};

#endif