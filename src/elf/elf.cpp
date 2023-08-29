#include "elf.hpp"
#include <errno.h>
#include <string.h>

/**
 * @brief Construct a new Program Header
 * 
 * @param t bit type 32/64
 * @param file_offset where in file
 * @param file file ptr
 */
ProgramHeader::ProgramHeader(bit_type t, uint64_t file_offset, FILE* file) {
    // have to deal w 32/64 bit differences in data sizes and such. ugh.
    // Probably not best convention, but I'll use fread() and fseek()
    fseek(file, file_offset, SEEK_SET);
    switch (t) {
        case IS_32BIT: {
            ph32 temp;
            fread(&temp, sizeof(ph32), 1, file);
            type = temp.type;
            flags = temp.flags;
            seg_offset = temp.seg_offset;
            vaddr = temp.vaddr;
            paddr = temp.paddr;
            seg_size_file = temp.seg_size_file;
            seg_size_mem = temp.seg_size_mem;
            alignment = temp.alignment;
            break;
        }
        case IS_64BIT: {
            ph64 temp;
            fread(&temp, sizeof(ph64), 1, file);
            type = temp.type;
            flags = temp.flags;
            seg_offset = temp.seg_offset;
            vaddr = temp.vaddr;
            paddr = temp.paddr;
            seg_size_file = temp.seg_size_file;
            seg_size_mem = temp.seg_size_mem;
            alignment = temp.alignment;
            break;
        }
    }
}

/**
 * @brief Construct a new Section Header object
 * 
 * @param t bit type 32/64
 * @param file_offset where in file
 * @param file ptr to file
 */
SectionHeader::SectionHeader(bit_type t, uint64_t file_offset, FILE* file) {
    // same as program header
    // the std::string name won't get set here. We will do that later
    // in the binary class itself.
    fseek(file, file_offset, SEEK_SET);
    switch (t) {
        case IS_32BIT: {
            sh32 temp;
            fread(&temp, sizeof(sh32), 1, file);
            name_idx = temp.name_idx;
            type = temp.type;
            flags = temp.flags;
            vaddr = temp.vaddr;
            file_offset = temp.file_offset;
            section_size = temp.section_size;
            sh_link = temp.sh_link;
            sh_info = temp.sh_info;
            align = temp.align;
            entry_size = temp.entry_size;
            break;
        }
        case IS_64BIT: {
            sh64 temp;
            fread(&temp, sizeof(sh64), 1, file);
            name_idx = temp.name_idx;
            type = temp.type;
            flags = temp.flags;
            vaddr = temp.vaddr;
            file_offset = temp.file_offset;
            section_size = temp.section_size;
            sh_link = temp.sh_link;
            sh_info = temp.sh_info;
            align = temp.align;
            entry_size = temp.entry_size;
            break;
        }
    }
}

void SectionHeader::setname(std::string name) {
    section_name = name;
}
std::string SectionHeader::getname() {
    return section_name;
}

Binary::~Binary() {
    delete[] strtab;
    pht.clear();
    sht.clear();
    fclose(file_handle);
}
Binary::Binary(std::string filepath) {
    file_handle = fopen(filepath.c_str(), "r");
    if (file_handle == NULL) {
        printf("Error : errno='%s'.\n", strerror(errno));
    }
    fseek(file_handle, 0, SEEK_SET);
    fread(&magic_number, sizeof(uint32_t), 1, file_handle);
    uint8_t type;
    fseek(file_handle, 4, SEEK_SET);
    fread(&type, sizeof(uint8_t), 1, file_handle);

    bit_type BIN_TYPE = (type == IS_32BIT) ? IS_32BIT : IS_64BIT;

    // Populate our elf header fields
    if (BIN_TYPE == IS_32BIT) {
        eh32 temp;
        fseek(file_handle, 0, SEEK_SET);
        fread(&temp, sizeof(eh32), 1, file_handle);
        endian = temp.endian;
        version = temp.version;
        abi = temp.abi;
        abi_ver = temp.abi_ver;
        binary_type = temp.binary_type;
        isa = temp.isa;
        elf_ver = temp.elf_ver;
        entrypoint = temp.entrypoint;
        ph_offset = temp.ph_offset;
        sh_offset = temp.sh_offset;
        flags = temp.flags;
        entry_header_size = temp.entry_header_size;
        ph_entry_size = temp.ph_entry_size;
        ph_num = temp.ph_num;
        sh_entry_size = temp.sh_entry_size;
        sh_num = temp.sh_num;
        sh_name_index = temp.sh_name_index;
    } else {
        eh64 temp;
        fseek(file_handle, 0, SEEK_SET);
        fread(&temp, sizeof(eh32), 1, file_handle);
        endian = temp.endian;
        version = temp.version;
        abi = temp.abi;
        abi_ver = temp.abi_ver;
        binary_type = temp.binary_type;
        isa = temp.isa;
        elf_ver = temp.elf_ver;
        entrypoint = temp.entrypoint;
        ph_offset = temp.ph_offset;
        sh_offset = temp.sh_offset;
        flags = temp.flags;
        entry_header_size = temp.entry_header_size;
        ph_entry_size = temp.ph_entry_size;
        ph_num = temp.ph_num;
        sh_entry_size = temp.sh_entry_size;
        sh_num = temp.sh_num;
        sh_name_index = temp.sh_name_index;
    }

    // populate program header table
    uint64_t ph_off_calc = ph_offset;
    for (int i = 0; i < ph_num; i++) {
        pht.push_back(ProgramHeader(BIN_TYPE, ph_off_calc, file_handle));
        ph_off_calc += ph_entry_size;
    }
    // populate section header table
    uint64_t sh_off_calc = sh_offset;
    for (int i = 0; i < sh_num; i++) {
        sht.push_back(SectionHeader(BIN_TYPE, sh_off_calc, file_handle));
        sh_off_calc += sh_entry_size;
    }

    strtab = new char[sht.at(sh_name_index).get_size()];
    // populate section header names
    uint64_t strings_offset = sht.at(sh_name_index).get_offset();
    fseek(file_handle, strings_offset, SEEK_SET);
    fread(strtab, sizeof(char), sht.at(sh_name_index).get_size(), file_handle);
    for (SectionHeader sh : sht) {
        std::string gen;
        uint32_t idx_in_strtab = sh.get_name_index();
        while (strtab[idx_in_strtab] != 0) {
            gen += strtab[idx_in_strtab];
            idx_in_strtab++;
        }
        sh.setname(gen);
        printf("%s\n", gen);
    }
}
// eof