#include "file_structs.h"

#ifndef DECODERS
#define DECODERS

// Helpers, convert RVA into file offset
uint32_t rvaToOffset32(PEFile32* exec, DWORD va);
uint32_t rvaToOffset64(PEFile64* exec, DWORD va);

void destroy32(PEFile32* file);
void destroy64(PEFile64* file);

/**
 * Validate PE File
*/
#define PE32 (32)
#define PE64 (64)
#define NOT_PE (-1)
#define pe32_magic (0x10B)
#define pe32plus_magic (0x20B)
#define rom_magic (0x107)
uint8_t validateFile(FILE* exec);

/**
 * Parse DOS header
*/
void parseDos32(PEFile32* file);
void parseDos64(PEFile64* file);

/**
 * Parse NT headers
*/
void parseNT32(PEFile32* file);
void parseNT64(PEFile64* file);

/**
 * Parse section headers
*/
void parseSection32(PEFile32* file);
void parseSection64(PEFile64* file);

/**
 * Import Directory handling
*/
void parseImportDir32(PEFile32* file);
void parseImportDir64(PEFile64* file);

/**
 * Base Relocations handling
*/
void parseRelocs32(PEFile32* file);
void parseRelocs64(PEFile64* file);

// Info and others
void dumpSections32(PEFile32* file);
void dumpSections64(PEFile64* file);

void dumpImports32(PEFile32* file);
void dumpImports64(PEFile64* file);

#endif /* end decode helpers */