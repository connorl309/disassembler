#include "elf_file.hpp"

const char* abinames[] = {
    "System V", "HP-UX", "NetBSD", "Linux", "GNU Hurd",
    "Unknown", "Solaris", "AIX Monterey", "IRIX", "FreeBSD",
    "Tru64", "Novell Modesto", "OpenBSD", "OpenVMS", "NonStop Kernel",
    "AROS", "FenixOS", "Nuxi CloudABI", "Stratus OpenVOS"
};
const char* typenames[] = {
    "Unknown", "REL", "EXEC", "DYN",
    "CORE"
};

ELF_File::ELF_File(FILE* input) {
    selectedFile = input;
    parse_elf_header();
    parse_program_table();
    parse_section_table();
    
    // Load up all the .text stuff
    returnSection code = getSectionData(".text");
    text_section_bytes = new uint8_t[code.sectionSize];
    fseek(selectedFile, code.image_offset, SEEK_SET);
    fread(text_section_bytes, sizeof(uint8_t), code.sectionSize, selectedFile);
    codeByteSize = code.sectionSize;
    codeFileOffset = code.image_offset;
}
uint8_t* ELF_File::expose_code() {
    return text_section_bytes;
}
ELF_File::~ELF_File() {
    if (is32) {
        delete static_cast<ELF_Header32*>(ElfHeader);
        delete[] static_cast<Program_Header_Entry32*>(ProgramHeaderTable);
        delete[] static_cast<Section_Header_Entry32*>(SectionHeaderTable);
    } else {
        delete static_cast<ELF_Header64*>(ElfHeader);
        delete[] static_cast<Program_Header_Entry64*>(ProgramHeaderTable);
        delete[] static_cast<Section_Header_Entry64*>(SectionHeaderTable);
    }
    delete[] text_section_bytes;
}
void ELF_File::basicInfo() {
    ELF_Header32* Aself32 = static_cast<ELF_Header32*>(ElfHeader);
    ELF_Header64* Aself64 = static_cast<ELF_Header64*>(ElfHeader);
    printf("ELF Header information:\n");
    printf("* Magic Number: \t");
    for (int i = 0; i < 4; i++) printf("%X ", Aself32->elf_magic[i]);
    printf("\n* Class:\t\t");
    (is32) ? printf("ELF 32-bit\n") : printf("ELF 64-bit\n");
    printf("* ABI: \t\t\t%s\n", abinames[Aself32->elf_abi]);
    if (Aself32->elf_type < 10) printf("* File type: \t\t%s\n", typenames[Aself32->elf_type]);
    printf("* Machine ISA: \t\t");
    if (Aself32->elf_machine_isa == 0x3E) printf("AMD x86-64\n");
    else if (Aself32->elf_machine_isa == 3) printf("Intel x86\n");
    else printf("%X, not named in this program\n", Aself32->elf_machine_isa);
    (is32) ? printf("* Entry point: \t\t0x%X\n", Aself32->entry_point) : printf("* Entry point: \t\t0x%lX\n", Aself64->entry_point);
    printf("\nProgram and Section header information:\n");
    if (is32) {
        printf("* Program header table offset: \t0x%X\n", Aself32->program_header_offset);
        printf("* Section header table offset: \t0x%X\n", Aself32->section_header_offset);
        printf("* No. of program headers: \t%d\n", Aself32->program_header_count);
        printf("* No. of section headers: \t%d\n", Aself32->section_header_count);
    } else {
        printf("* Program header table offset: \t0x%lX\n", Aself64->program_header_offset);
        printf("* Section header table offset: \t0x%lX\n", Aself64->section_header_offset);
        printf("* No. of program headers: \t%d\n", Aself64->program_header_count);
        printf("* No. of section headers: \t%d\n", Aself64->section_header_count);
    }
}

void ELF_File::dumpSectionEntries() {
    // So we know the section table starts at file + header offset from ELF
    // and each section will be fixed size (hopefully...)
    Section_Header_Entry32* as32 = static_cast<Section_Header_Entry32*>(SectionHeaderTable);
    Section_Header_Entry64* as64 = static_cast<Section_Header_Entry64*>(SectionHeaderTable);
    printf("\nSection headers\n");
    for (int i = 0; i < numberOfSectionHeaders; i++) {
        int a = 0;
        printf("\nSection name offset: \t%X\n", as32[i].sectionNameOffset);
        printf("Section type: \t%X\n", as32[i].sectionType);
        if (is32) {
            printf("Section flags: \t%X\n", as32[i].flags);
            printf("Section VA: \t%X\n", as32[i].sectionVA);
            printf("Section Offset: \t%X (from file image)\n", as32[i].sectionFileOffset);
            printf("Section size: \t%X\n", as32[i].sectionFileSize);
            printf("Section alignment: \t%d\n", as32[i].addressAlign);
        } else {
            printf("Section flags: \t%lX\n", as64[i].flags);
            printf("Section VA: \t%lX\n", as64[i].sectionVA);
            printf("Section Offset: \t%lX (from file image)\n", as64[i].sectionFileOffset);
            printf("Section size: \t%lX\n", as64[i].sectionFileSize);
            printf("Section alignment: \t%ld\n", as64[i].addressAlign);
        }
    }
}

// Parse Elf header of a file
void ELF_File::parse_elf_header() {
    // we're going to assume that the file is opened already
    int size = 0;
    fseek(selectedFile, 4, SEEK_SET);
    fread(&size, sizeof(uint8_t), 1, selectedFile);
    fseek(selectedFile, 0, SEEK_SET);
    // we can also create our tables here bc we know size
    if (size == 1) { // 32 bit
        ElfHeader = new ELF_Header32;
        fread(ElfHeader, sizeof(ELF_Header32), 1, selectedFile);
        is32 = true;
        ELF_Header32* casted = static_cast<ELF_Header32*>(ElfHeader);
        ProgramHeaderTable = new Program_Header_Entry32[casted->program_header_count];
        SectionHeaderTable = new Section_Header_Entry32[casted->section_header_count];
        numberOfProgramHeaders = casted->program_header_count;
        numberOfSectionHeaders = casted->section_header_count;
        sectionTableOff = casted->section_header_offset;
        casted->elf_abi--;
    } else if (size == 2) { // 64 bit
        ElfHeader = new ELF_Header64;
        fread(ElfHeader, sizeof(ELF_Header64), 1, selectedFile);
        is32 = false;
        ELF_Header64* casted = static_cast<ELF_Header64*>(ElfHeader);
        ProgramHeaderTable = new Program_Header_Entry64[casted->program_header_count];
        SectionHeaderTable = new Section_Header_Entry64[casted->section_header_count];
        numberOfProgramHeaders = casted->program_header_count;
        numberOfSectionHeaders = casted->section_header_count;
        sectionTableOff = casted->section_header_offset;
        casted->elf_abi--;
    } else {
        printf("Unknown file class (not 32 bit or 64 bit)!\n");
        printf("Got class: %d\n", size);
    }
}

// Populate program header table
void ELF_File::parse_program_table() {
    uint32_t off32 = static_cast<ELF_Header32*>(ElfHeader)->program_header_offset;
    uint64_t off64 = static_cast<ELF_Header64*>(ElfHeader)->program_header_offset;
    // program header table starts at file + program_header_offset
    // 32 bit
    if (is32) {
        fseek(selectedFile, off32, SEEK_SET);
        fread(ProgramHeaderTable, sizeof(Program_Header_Entry32), numberOfProgramHeaders, selectedFile);
    } else { // 64 bit
        fseek(selectedFile, off64, SEEK_SET);
        fread(ProgramHeaderTable, sizeof(Program_Header_Entry64), numberOfProgramHeaders, selectedFile);
    }
}

// Populate section header table
void ELF_File::parse_section_table() {
    uint32_t off32 = static_cast<ELF_Header32*>(ElfHeader)->section_header_offset;
    uint64_t off64 = static_cast<ELF_Header64*>(ElfHeader)->section_header_offset;
    // section header table starts at file + section offset
    // 32 bit
    if (is32) {
        fseek(selectedFile, off32, SEEK_SET);
        fread(SectionHeaderTable, sizeof(Section_Header_Entry32), numberOfSectionHeaders, selectedFile);
    } else { // 64 bit
        fseek(selectedFile, off64, SEEK_SET);
        fread(SectionHeaderTable, sizeof(Section_Header_Entry64), numberOfSectionHeaders, selectedFile);
    }
}
