#ifndef elf_file
#define elf_file

/**
 * https://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/docs/elf.pdf
*/

#include <stdint.h>
#include <stdio.h> // might want to use C++ stuff. but for now FILE*

// ELF header useful defines
// file type
#define elf32 (1)
#define elf64 (2)

// An ELF header
struct ELF_Header32 {
    uint8_t elf_magic[4]; // should be 7F 45 4C 46
    uint8_t elf_class; // 1 for 32, or 2 for 64 bit
    uint8_t elf_endianness;
    uint8_t elf_abi;
    // if statically linked, elf_abiv + pad are pad bytes
    // if dynamically linked, pad[7] is correct anyways.
    uint8_t elf_abiv;
    uint8_t pad[7];
    uint16_t elf_type; // 0 unknown, 1 relocatable, 2 executable, 3 shared object, 4 core. anything else whatever
    uint16_t elf_machine_isa; // only care about x86 and amdx86-64 for now.
    uint32_t elf_version;
    // 32/64 dep
    uint32_t entry_point;
    uint32_t program_header_offset;
    uint32_t section_header_offset;
    //
    uint32_t elf_flags;
    uint16_t elf_header_size;
    uint16_t program_header_entry_size;
    uint16_t program_header_count;
    uint16_t section_header_entry_size;
    uint16_t section_header_count;
    uint16_t section_name_index;
};
struct ELF_Header64 {
    uint8_t elf_magic[4]; // should be 7F 45 4C 46
    uint8_t elf_class; // 1 for 32, or 2 for 64 bit
    uint8_t elf_endianness;
    uint8_t elf_abi;
    // if statically linked, elf_abiv + pad are pad bytes
    // if dynamically linked, pad[7] is correct anyways.
    uint8_t elf_abiv;
    uint8_t pad[7];
    uint16_t elf_type; // 0 unknown, 1 relocatable, 2 executable, 3 shared object, 4 core. anything else whatever
    uint16_t elf_machine_isa; // only care about x86 and amdx86-64 for now.
    uint32_t elf_version;
    // 32/64 dependent
    uint64_t entry_point;
    uint64_t program_header_offset;
    uint64_t section_header_offset;
    //
    uint32_t elf_flags;
    uint16_t elf_header_size;
    uint16_t program_header_entry_size;
    uint16_t program_header_count;
    uint16_t section_header_entry_size;
    uint16_t section_header_count;
    uint16_t section_name_index;
};

// Program header
struct Program_Header_Entry32 {
    uint32_t type;
    uint32_t segmentOffset;
    uint32_t segmentVA;
    uint32_t segmentPA; // only on systems where PA is used
    uint32_t segmentFileSize; // size on the file image
    uint32_t segmentMemSize;
    uint32_t flags;
    uint32_t alignment; // 0 and 1 are no align. otherwise, alignment should be a power of 2, and VA = offset % align
};
struct Program_Header_Entry64 {
    uint32_t type;
    uint32_t flags;
    uint64_t segmentOffset;
    uint64_t segmentVA;
    uint64_t segmentPA; // only on systems where PA is used
    uint64_t segmentFileSize; // size on the file image
    uint64_t segmentMemSize;
    uint64_t alignment; // 0 and 1 are no align. otherwise, alignment should be a power of 2, and VA = offset % align
};

// Section header
struct Section_Header_Entry32 {
    uint32_t sectionNameOffset; // offset into .shstrtab representing name of section
    uint32_t sectionType;
    uint32_t flags;
    uint32_t sectionVA;
    uint32_t sectionFileOffset;
    uint32_t sectionFileSize;
    uint32_t sectionIndex;
    uint32_t sectionInfo;
    uint32_t addressAlign; // must be 2^
    uint32_t entrySize;
};
struct Section_Header_Entry64 {
    uint32_t sectionNameOffset; // offset into .shstrtab representing name of section
    uint32_t sectionType;
    uint64_t flags;
    uint64_t sectionVA;
    uint64_t sectionFileOffset;
    uint64_t sectionFileSize;
    uint32_t sectionIndex;
    uint32_t sectionInfo;
    uint64_t addressAlign; // must be 2^
    uint64_t entrySize;
};

// a symbol table entry
struct Symbol_Table_Entry32 {
    uint32_t st_name; // index into .strtab
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    // which section do we belong to
    uint16_t st_shndx;
};
struct Symbol_Table_Entry64 {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx; // index into .strtab
    uint64_t st_value;
    uint64_t st_size;
};

// helpers and stuff
typedef struct {
    uint64_t image_offset;
    uint64_t sectionSize;
} returnSection;

// AN ELF FILE CLASS
class ELF_File {

private:
    void* ElfHeader;
    void* ProgramHeaderTable;
    void* SectionHeaderTable;
    void* SymbolTable;

    FILE* selectedFile;
    uint64_t numberOfSectionHeaders;
    uint64_t numberOfProgramHeaders;
    uint64_t sectionTableOff;
    bool is32;
    
    void parse_elf_header();
    void parse_program_table();
    void parse_section_table(); 
public:
    ELF_File(FILE* input);
    ~ELF_File();
    void basicInfo();
    void dumpSectionEntries();
    uint64_t findSectionByName(const char* name, bool cliHelp);
    returnSection getSectionData(const char* name);
    returnSection getSectionDataIndex(uint64_t index);
    // return a pointer to an array containing section data, in bytes
    // MUST BE DELETED[] BY CALLER
    uint8_t* sectionArray(returnSection abc);
    uint64_t fileAddress();
};

#endif /* End ELF definition header */