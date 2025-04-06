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
    uint64_t current_offset;
    uint64_t dymsym_header_offset;
    uint64_t sym_header_offset;
};

struct Symbol
{
    std::string name;
    uint64_t address;
    uint64_t size;
    uint8_t info;
    uint16_t section_index;
    bool executable;
};

bool loadELF(const std::string &filename, ELFFile &elfFile);
bool getEntryOffset(ELFFile &elfFile);
void printSymbolNames(const std::vector<Symbol> &symbols);
std::vector<Symbol> parseSymbolTable(ELFFile &elfFile);
