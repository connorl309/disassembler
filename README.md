# disassembler
A little hobby disassembler, leveraging the [Capstone disassembly engine](https://www.capstone-engine.org/lang_c.html).

Features a custom binary parser, currently supporting ELF files, with planned support for the Windows PE format.
Can dump section information, headers, raw data, etc.

Originally written in mostly C, but now rewriting in C++ (see branches).
