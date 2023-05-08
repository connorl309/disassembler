/**
 * PE (Portable Executable) files have a nice standard file structure (thank god)
 * https://0xrick.github.io/win-internals/pe1/
 * Structure:
 * DOS HEADER
 * DOS STUB
 * NT HEADERS (signature, other headers)
 * SECTION TABLE
 * Sections (i.e. .data, .text, .code etc)
 * 
 * A lot of this is pulled pretty much word for word (get it?) from winnt.h
*/

#ifndef filestructdefs
#define filestructdefs

#include <stdint.h>
#include <stdio.h>

// The Windows documentation for PE headers is nice
// Also, a lot of this is copy pasted because I do not want to manually type out every single
// field needed.
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD, LONG;

// TODO: Specify all the Characteristics flag values

#define DATA_DIR_ENTRIES 16
#define DOS_MAGIC (0x5A4D)

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

// Need definitions for section headers
// section headers are 40 bytes total with NO PADDING, but cant guarantee this
#define SECTION_HEADER_SIZE (40)
typedef struct {
    BYTE SectionName[8]; // fixed
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc; // not sure why this is a union...
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} section_header;

// Import tables
// Import Directory Table, Import Lookup Table, Import Address Table

/**
 * Import Directory Table is a data directory at beginning of .idata,
 * and is an array of structs describing DLLs
*/
typedef struct {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk; // RVA of the lookup table
    } dummy;
    DWORD datetime;
    DWORD ForwarderChain; // index stuff used for DLL forwarding
    DWORD Name; // RVA for ascii string containing DLL name
    DWORD FirstThunk; // RVA for address table
} import_descriptor;

/**
 * Bounded imports are static, fixed addresses for
 * imported functions. Calculated at compile time.
*/
typedef struct {
    DWORD datetime;
    WORD OffsetModuleName; // offset to string of DLL, offset from the very first bound_descriptor
    WORD NumberOfModuleForwarderRefs;
} bound_descriptor;
typedef struct {
    WORD Hint;
    char Name[100];
} import_by_name;
/**
 * Lookup table (or name table, INT)
 * Every DLL has a lookup table. IMPORT_DESCRIPTOR.ORIGINALFIRSTTHUNK has the RVA of the ILT for the corresponding
 * DLL
*/
typedef struct {
    union {
        DWORD Ordinal : 16;
        DWORD HintNameTabe : 32;
        DWORD OrdinalNameFlag : 1;
    } Field;
} ilt32;
typedef struct {
    union {
        DWORD ORDINAL : 16;
        DWORD HintNameTabe : 32;
    } Field;
    DWORD OrdinalNameFlag : 1;
} ilt64;

/**
 * Relocation tables
 * 
 * Image loader tries to adjust offsets/addresses when its wrong, relocating
 * the relocation table contains entries for ALL of these relocations
*/
typedef struct {
    DWORD VirtualAddress; // RVA of a page where relocation is (i.e., true VA is image base + this value)
    DWORD SizeOfBlock;
} relocation_base;
typedef struct {
    WORD offset : 12;
    WORD type : 4;
} relocation_entry;

// An actual PE file struct. 
// Lots of variables here. :)

// This is for 64 bit PE Files
typedef struct {
    // Basic file info
    char* filename;
    FILE* realFile;
    int importDirectoryCount, importDirectorySize, relocationDirectoryCount;

    // Headers
    dos_header PE_DosHeader;
    nt_header64 PE_NTHeader;

    // Directories
    data_directory exportDir;
    data_directory importDir;
    data_directory resourceDir;
    data_directory relocationDir;
    data_directory iatDir;
    data_directory globalPointerDir;
    data_directory exceptionDir;
    data_directory securityDir, debugDir, tlsDir, loadConfigDir, boundImportDir, delayImportDir, comDescriptorDir;

    // Section headers
    section_header* PE_SectionHeaders;
    // Import table
    import_descriptor* PE_ImportTable;
    // Reloc table
    relocation_base* PE_BaseRelocationTable;
} PEFile64;

// This is for 32 bit PE files
typedef struct {
    // Basic file info
    char* filename;
    FILE* realFile;
    int importDirectoryCount, importDirectorySize, relocationDirectoryCount;

    // Headers
    dos_header PE_DosHeader;
    nt_header32 PE_NTHeader; // literally the only change

    // Directories
    data_directory exportDir;
    data_directory importDir;
    data_directory resourceDir;
    data_directory relocationDir;
    data_directory iatDir;
    data_directory globalPointerDir;
    data_directory exceptionDir;
    data_directory securityDir, debugDir, tlsDir, loadConfigDir, boundImportDir, delayImportDir, comDescriptorDir;

    // Section headers
    section_header* PE_SectionHeaders;
    // Import table
    import_descriptor* PE_ImportTable;
    // Reloc table
    relocation_base* PE_BaseRelocationTable;
} PEFile32;

/* Icky... */
/* These are indexes into the DataDirectory array */
#define IMAGE_FILE_EXPORT_DIRECTORY		0
#define IMAGE_FILE_IMPORT_DIRECTORY		1
#define IMAGE_FILE_RESOURCE_DIRECTORY		2
#define IMAGE_FILE_EXCEPTION_DIRECTORY		3
#define IMAGE_FILE_SECURITY_DIRECTORY		4
#define IMAGE_FILE_BASE_RELOCATION_TABLE	5
#define IMAGE_FILE_DEBUG_DIRECTORY		6
#define IMAGE_FILE_DESCRIPTION_STRING		7
#define IMAGE_FILE_MACHINE_VALUE		8  /* Mips */
#define IMAGE_FILE_THREAD_LOCAL_STORAGE		9
#define IMAGE_FILE_CALLBACK_DIRECTORY		10

/* Directory Entries, indices into the DataDirectory array */

#define	IMAGE_DIRECTORY_ENTRY_EXPORT		0
#define	IMAGE_DIRECTORY_ENTRY_IMPORT		1
#define	IMAGE_DIRECTORY_ENTRY_RESOURCE		2
#define	IMAGE_DIRECTORY_ENTRY_EXCEPTION		3
#define	IMAGE_DIRECTORY_ENTRY_SECURITY		4
#define	IMAGE_DIRECTORY_ENTRY_BASERELOC		5
#define	IMAGE_DIRECTORY_ENTRY_DEBUG		6
#define	IMAGE_DIRECTORY_ENTRY_COPYRIGHT		7
#define	IMAGE_DIRECTORY_ENTRY_GLOBALPTR		8   /* (MIPS GP) */
#define	IMAGE_DIRECTORY_ENTRY_TLS		9
#define	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	10
#define	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	11
#define	IMAGE_DIRECTORY_ENTRY_IAT		12  /* Import Address Table */
#define	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	13
#define	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14

/* DLL Characteristics */
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND               0x0800
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            0x2000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

#endif /* end of include guard for file_structs */