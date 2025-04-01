#include <elf.h>
#include <fstream>
#include <vector>
#include <cstdint>
#include <inttypes.h>
#include <elf.h>
#include <iostream>
#include <set>

struct ELFFile
{
    std::vector<uint8_t> data;
    uint64_t entry_offset;
    uint64_t dymsym_header_offset;
    uint64_t sym_header_offset;
};

bool loadELF(const std::string &filename, ELFFile &elfFile);
bool getEntryOffset(ELFFile &elfFile);

