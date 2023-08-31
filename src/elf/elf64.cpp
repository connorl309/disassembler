#include "elf64.hpp"
#include <error.h>
#include <string.h>
#include <assert.h>

/**
 * @brief Construct a new Binary object
 * 
 * @param filepath Path to executable file
 */
Binary64::Binary64(FILE* file)
{
    // Open file
    handle = file;
    if (!handle) {
        printf("Could not open executable, error: %s\n", strerror(errno));
    }
    // we know we're 64 bit so read 0x34 bytes of data into elf header
    fseek(handle, 0, SEEK_SET);
    fread(&elf_header, sizeof(ElfHeader64), 1, handle);
    sections = elf_header.e_shnum;

    // Sanity checks
    assert(sizeof(SectionHeader64) == elf_header.e_shentsize);
    assert(sizeof(ProgramHeader64) == elf_header.e_phentsize);

    // Populate section table
    section_header_table = new SectionHeader64[sections];
    fseek(handle, elf_header.e_shoff, SEEK_SET);
    fread(section_header_table, sizeof(SectionHeader64), sections, handle);

    // Populate program header table
    program_header_table = new ProgramHeader64[elf_header.e_phnum];
    fseek(handle, elf_header.e_phoff, SEEK_SET);
    fread(program_header_table, sizeof(ProgramHeader64), elf_header.e_phnum, handle);

    // Populate the section map
    // maps section names (strings) to a pointer to the corresponding section
    // store a temp array of the section name table here.
    uint64_t nametable_size = section_header_table[elf_header.e_shstrndx].sh_size;
    char* nametable = new char[nametable_size];
    // read in the entire table (might be bad practice but I don't want to do tons of fseeks and freads)
    fseek(handle, section_header_table[elf_header.e_shstrndx].sh_offset, SEEK_SET);
    fread(nametable, sizeof(char), nametable_size, handle);
    for (uint16_t i = 0; i < sections; i++) {
        uint64_t name_idx = section_header_table[i].sh_name;
        std::string name;
        while (nametable[name_idx] != '\0') {
            name += nametable[name_idx];
            name_idx++;
        }
        section_map.emplace(name, &section_header_table[i]);
        reverse_section_map.emplace(&section_header_table[i], name);
    }
    delete[] nametable; // memory cleanup
}

/**
 * Print the Elf header for the binary
 */
void Binary64::printHeader() {
    printf("-- EXECUTABLE INFORMATION (64-bit): ELF HEADER --\n");
    printf("  Binary Class:\t\t\tELF64\n");
    printf("  Binary OS/ABI:\t\t\t0x%02X\n", elf_header.ei_osabi);
    printf("  Binary Type:\t\t\t0x%02X\n", elf_header.e_type);
    printf("  Binary ISA:\t\t\t0x%02X\n", elf_header.e_machine);
    printf("  Binary Execution Entrypoint:\t\t\t0x%08X\n", elf_header.e_entry);
    printf("  Start of program headers:\t\t\t0x%08X (bytes into file)\n", elf_header.e_phoff);
    printf("  Size of a program header:\t\t\t%d (in bytes)\n", elf_header.e_phentsize);
    printf("  Start of section headers:\t\t\t0x%08X (bytes into file)\n", elf_header.e_shoff);
    printf("  Size of a section header:\t\t\t%d (in bytes)\n", elf_header.e_shentsize);
    printf("  Number of program headers: %d\n", elf_header.e_phnum);
    printf("  Number of section headers:\t\t\t%d / %d\n", elf_header.e_phnum, elf_header.e_shnum);
}
/**
 * Print every section and some relevant information
 */
void Binary64::dumpSections() {
    for (uint16_t i = 0; i < sections; i++) {
        std::string name = reverse_section_map.at(&section_header_table[i]);
        uint64_t file_off = section_header_table[i].sh_offset;
        uint64_t size = section_header_table[i].sh_size;
        printf("\nSection [%s]\n", name);
        printf("\t* File Offset: 0x%08X\n", file_off);
        printf("\t* Section Size: 0x%08X\n", size);
        printf("\t* Section Flags: 0x%08X\n", section_header_table[i].sh_flags); // todo: maybe implement lut for flag enum and string
    }
}
/**
 * Dump a section's bytes to a file
 */
void Binary64::dumpSectionBytes(std::string sectionName) {
    SectionHeader64* section = section_map.at(sectionName);
    // I want to make this memory efficient, so we'll
    // read/write ~30 bytes at a time.
    FILE* dumped = fopen(sectionName.c_str(), "w+");
    if (!dumped) {
        printf("Could not create file for byte dump. Error: %s", strerror(errno));
    }
    uint64_t bytes_left = section->sh_size;
    uint64_t offset = section->sh_offset;
    char buffer[30];
    memset(buffer, 0, 30);
    while (bytes_left > 30) {
        // Write address
        snprintf(buffer, 30, "0x%08X: ", offset);
        fwrite(buffer, sizeof(char), 30, dumped);
        // Read the section data
        fseek(handle, offset, SEEK_SET);
        fread(buffer, sizeof(char), 30, handle);
        offset += 30;
        // Format and write data
        for (char c : buffer) {
            fputc(c, dumped);
            fputc(' ', dumped);
        }
        fputc('\n', dumped);
        memset(buffer, 0, 30);
    }
}