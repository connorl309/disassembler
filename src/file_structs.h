/**
 * PE (Portable Executable) files have a nice standard file structure (thank god)
 * https://0xrick.github.io/win-internals/pe1/
 * Structure:
 * DOS HEADER
 * DOS STUB
 * NT HEADERS (signature, other headers)
 * SECTION TABLE
 * Sections (i.e. .data, .text, .code etc)
*/

#ifndef PARSE
#define PARSE

#include <stdint.h>

// The Windows documentation for PE headers is nice
// Also, a lot of this is copy pasted because I do not want to manually type out every single
// field needed.
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD, LONG;

#define DATA_DIR_ENTRIES 16

// DOS header
typedef struct {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} dos_header;

// data directory
typedef struct {
    DWORD virtual_address;
    DWORD size;
} data_directory;

// optional header PE32 only
typedef struct {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    data_directory DataDirectory[DATA_DIR_ENTRIES];
} optional_header32;

// optional header PE32+
typedef struct {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    QWORD       ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    QWORD       SizeOfStackReserve;
    QWORD       SizeOfStackCommit;
    QWORD       SizeOfHeapReserve;
    QWORD       SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    data_directory DataDirectory[DATA_DIR_ENTRIES];
} optional_header64;

// File header
typedef struct {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} file_header;

// NT 64 bit header
typedef struct {
    DWORD Signature;
    file_header FileHeader;
    optional_header64 optional;
} nt_header64;
// NT 32 bit header
typedef struct {
    DWORD Signature;
    file_header FileHeader;
    optional_header32 optional;
} nt_header32;

#endif