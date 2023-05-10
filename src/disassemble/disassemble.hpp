#ifndef disasm
#define disasm
// Pain and suffering. x86, you evil thing.
#include <stdint.h>
#include <stdlib.h>

// https://users.ece.utexas.edu/~patt/22s.382N/handouts/x86%20Instruction%20Set%20Reference.pdf
// PDF page30
const uint8_t lock_rep_prefixes[] = {0xF0, 0xF2, 0xF3};
const uint8_t seg_override_prefixes[] = {0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65};
const uint8_t branch_hint_prefixes[] = {0x2e, 0x3e};
const uint8_t size_override_prefixes[] = {0x66, 0x67};

// For parsing
#define OPCODE_ARRAY_TERMINATION 0xFFFFFFFF
typedef struct {
    uint16_t bytes[15]; // x86 instructions can be a (functional) maximum of 15 bytes
                        // the above #define is loaded into any unused bytes. maybe. I don't know how I'm doing this.
} opcode_array;

#endif /* end disassemble header */