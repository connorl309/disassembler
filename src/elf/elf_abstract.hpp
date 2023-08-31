#ifndef E_ABS_H
#define E_ABS_H

#include <stdint.h>
#include <stdlib.h>
#include <string>

class ElfBinary
{
public:
    virtual void dumpSections() = 0;
    virtual void printHeader() = 0;
    virtual void dumpSectionBytes(std::string sectionName) = 0;
};

#endif