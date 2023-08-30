#ifndef E_ABS_H
#define E_ABS_H

#include <stdint.h>
#include <stdlib.h>
#include <string>

class ElfBinary
{
public:
    virtual void dumpSections();
    virtual void printHeader();
    virtual void dumpSectionBytes(std::string sectionName);
};

#endif