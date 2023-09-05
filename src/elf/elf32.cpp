#include "elf32.hpp"
#include <error.h>
#include <string.h>
#include <assert.h>

/**
 * @brief Construct a new Binary object
 * 
 * @param filepath Path to executable file
 */
Binary32::Binary32(FILE* file)
{
    // Open file
    handle = file;
    if (!handle) {
        printf("Could not open executable, error: %s\n", strerror(errno));
    }
    // we know we're 32 bit so read 0x34 bytes of data into elf header
    fseek(handle, 0, SEEK_SET);
    fread(&elf_header, sizeof(ElfHeader32), 1, handle);
    sections = elf_header.e_shnum;

    // Sanity checks
    assert(sizeof(SectionHeader32) == elf_header.e_shentsize);
    assert(sizeof(ProgramHeader32) == elf_header.e_phentsize);

    // Populate section table
    section_header_table = new SectionHeader32[sections];
    fseek(handle, elf_header.e_shoff, SEEK_SET);
    fread(section_header_table, sizeof(SectionHeader32), sections, handle);

    // Populate program header table
    program_header_table = new ProgramHeader32[elf_header.e_phnum];
    fseek(handle, elf_header.e_phoff, SEEK_SET);
    fread(program_header_table, sizeof(ProgramHeader32), elf_header.e_phnum, handle);

    // Populate the section map
    // maps section names (strings) to a pointer to the corresponding section
    // store a temp array of the section name table here.
    uint32_t nametable_size = section_header_table[elf_header.e_shstrndx].sh_size;
    char* nametable = new char[nametable_size];
    // read in the entire table (might be bad practice but I don't want to do tons of fseeks and freads)
    fseek(handle, section_header_table[elf_header.e_shstrndx].sh_offset, SEEK_SET);
    fread(nametable, sizeof(char), nametable_size, handle);
    for (uint16_t i = 0; i < sections; i++) {
        uint32_t name_idx = section_header_table[i].sh_name;
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
void Binary32::printHeader() {
    printf("-- EXECUTABLE INFORMATION (32-bit): ELF HEADER --\n");
    printf("  Binary Class:\t\t\tELF32\n");
    printf("  Binary OS/ABI:\t\t\t0x%02X\n", elf_header.ei_osabi);
    printf("  Binary Type:\t\t\t0x%02X\n", elf_header.e_type);
    printf("  Binary ISA:\t\t\t0x%02X\n", elf_header.e_machine);
    printf("  Binary Execution Entrypoint:\t\t\t0x%04X\n", elf_header.e_entry);
    printf("  Start of program headers:\t\t\t0x%04X\n (bytes into file)", elf_header.e_phoff);
    printf("  Size of a program header:\t\t\t%d (in bytes)\n", elf_header.e_phentsize);
    printf("  Start of section headers:\t\t\t0x%04X\n (bytes into file)", elf_header.e_shoff);
    printf("  Size of a section header:\t\t\t%d (in bytes)\n", elf_header.e_shentsize);
    printf("  Number of program headers / Number of section headers:\t\t\t%d / %d\n", elf_header.e_phnum, elf_header.e_shnum);
}
/**
 * Print every section and some relevant information
 */
void Binary32::dumpSections() {
    for (uint16_t i = 0; i < sections; i++) {
        std::string name = reverse_section_map.at(&section_header_table[i]);
        uint32_t file_off = section_header_table[i].sh_offset;
        uint32_t size = section_header_table[i].sh_size;
        printf("\nSection [%s]\n", name.c_str());
        printf("\t* File Offset: 0x%X (%d bytes into file)\n", file_off, file_off);
        printf("\t* Section Size: %d bytes\n", size);
        printf("\t* Section Flags: 0x%04X\n", section_header_table[i].sh_flags); // todo: maybe implement lut for flag enum and string
    }
}
/**
 * Dump a section's bytes to a file
 */
void Binary32::dumpSectionBytes(std::string sectionName) {
    // Copy+pasted from elf64.cpp
    SectionHeader32* section = section_map.at(sectionName);
    FILE* dumped = fopen("section_dump.txt", "a+");
    if (!dumped) {
        printf("Could not create file for byte dump. Error: %s", strerror(errno));
    }
    uint64_t size = section->sh_size;
    uint64_t bytes_left = size;
    uint64_t offset = section->sh_offset;
    fprintf(dumped, "\nDump of section: %s\n", sectionName.c_str());

#define PERLINE 16
    
    uint8_t buffer[PERLINE];
    // This isn't super optimal but honestly I dont know better ways
    // to copy raw bytes of data between files.
    for ( size_t i = 0; i + PERLINE < size; i += PERLINE) {
        // read bytes from section into buffer
        fseek(handle, offset, SEEK_SET); // go to the start of data
        fread(buffer, sizeof(char), PERLINE, handle);
        // print addr
        fprintf(dumped, "0x%08lX: ", offset + i);
        for (uint8_t c : buffer) {
            fprintf(dumped, "%02x ", c);
        }
        fprintf(dumped, "\t");
        // now print the string equivalent
        for (uint8_t c : buffer) {
            uint8_t toWrite = (c != 0) ? c : (uint8_t)0x7C; // GCC yelling at me; this is the | character
            fprintf(dumped, "%c", toWrite);
        }
        fprintf(dumped, "\n");
        bytes_left -= PERLINE;
        offset += PERLINE;
    }
    // handle any remaining data
    if (bytes_left != 0) {
        fseek(handle, offset, SEEK_SET);
        fread(buffer, sizeof(char), bytes_left, handle);
        fprintf(dumped, "0x%08lX: ", offset + bytes_left);
        for (uint8_t c : buffer) {
            fprintf(dumped, "%02x ", c);
        }
        fprintf(dumped, "\t");
        // now print the string equivalent
        for (uint8_t c : buffer) {
            uint8_t toWrite = (c != 0) ? c : (uint8_t)0x7C; // GCC yelling at me; this is the | character
            fprintf(dumped, "%c", toWrite);
        }
    }
    fclose(dumped);
}

/**
 * Cleanup func (calls destructor)
*/
void Binary32::cleanup() {
    this->~Binary32();
}