#include <elf.h>
#include <fstream>
#include <vector>
#include <cstdint>
#include <inttypes.h>
#include <elf.h>
#include <iostream>
#include <set>
#include "elf_parser.h"

bool loadELF(const std::string &filename, ELFFile &elfFile)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cerr << "Failed to open ELF file: " << filename << "\n";
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    elfFile.data.resize(size);

    if (!file.read(reinterpret_cast<char *>(elfFile.data.data()), size))
    {
        std::cerr << "Failed to read ELF file." << std::endl;
        return false;
    }

    return true;
}

bool getEntryOffset(ELFFile &elfFile)
{
    if (elfFile.data.size() < sizeof(Elf64_Ehdr))
    {
        std::cerr << "Invalid ELF file." << std::endl;
        return false;
    }

    Elf64_Ehdr *header = reinterpret_cast<Elf64_Ehdr *>(elfFile.data.data());
    Elf64_Phdr *program_headers = reinterpret_cast<Elf64_Phdr *>(elfFile.data.data() + header->e_phoff);

    uint64_t entry_point = header->e_entry;
    uint64_t entry_offset = 0;

    for (int i = 0; i < header->e_phnum; i++)
    {
        Elf64_Phdr &ph = program_headers[i];
        if (ph.p_type == PT_LOAD && ph.p_vaddr <= entry_point && entry_point < ph.p_vaddr + ph.p_memsz)
        {
            entry_offset = entry_point - ph.p_vaddr + ph.p_offset;
            elfFile.entry_offset = entry_offset;
            return true;
        }
    }

    std::cerr << "Entry offset not found." << std::endl;
    return false;
}

std::vector<Symbol> parseSymbolTable(ELFFile &elfFile)
{
    std::vector<Symbol> symbols;

    if (elfFile.data.size() < sizeof(Elf64_Ehdr))
    {
        std::cerr << "Invalid ELF file." << std::endl;
        return symbols;
    }

    Elf64_Ehdr *header = reinterpret_cast<Elf64_Ehdr *>(elfFile.data.data());
    Elf64_Shdr *section_headers = reinterpret_cast<Elf64_Shdr *>(elfFile.data.data() + header->e_shoff);

    for (int i = 0; i < header->e_shnum; ++i)
    {
        Elf64_Shdr &sh = section_headers[i];
        if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM)
            continue;

        const Elf64_Sym *symtab = reinterpret_cast<const Elf64_Sym *>(elfFile.data.data() + sh.sh_offset);
        size_t symbol_count = sh.sh_size / sizeof(Elf64_Sym);

        const Elf64_Shdr &strtab_section = section_headers[sh.sh_link];
        const char *strtab = reinterpret_cast<const char *>(elfFile.data.data() + strtab_section.sh_offset);

        for (size_t j = 0; j < symbol_count; ++j)
        {
            const Elf64_Sym &sym = symtab[j];
            if (sym.st_name == 0)
                continue;

            Symbol s;
            Elf64_Shdr section;
            s.name = std::string(strtab + sym.st_name);
            s.address = sym.st_value;
            s.size = sym.st_size;
            s.info = sym.st_info;
            s.section_index = sym.st_shndx;
            if (s.section_index <= header->e_shnum)
            {
                section = section_headers[s.section_index];
                if ((section.sh_flags & SHF_EXECINSTR))
                {
                    s.executable = 1;
                }
                else
                {
                    s.executable = 0;
                }
            }
            symbols.push_back(s);
        }
    }
    return symbols;
}

void printSymbolNames(const std::vector<Symbol> &symbols)
{
    std::cout << "\nSymbols:\n";
    std::cout << "-----------------------------\n";
    for (const auto &sym : symbols)
    {
        std::cout << sym.name << " @ 0x" << std::hex << sym.address << std::dec << "\n";
    }
    std::cout << "-----------------------------\n";
}
