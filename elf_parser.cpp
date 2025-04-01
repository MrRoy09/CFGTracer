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

bool getSymbolTable(ELFFile &elfFile){
     if (elfFile.data.size() < sizeof(Elf64_Ehdr))
    {
        std::cerr << "Invalid ELF file." << std::endl;
        return false;
    }

    Elf64_Ehdr *header = reinterpret_cast<Elf64_Ehdr *>(elfFile.data.data());

    uint64_t section_offset = header->e_shoff;
    uint64_t number_sections = header->e_shnum;
    size_t size_section = header->e_shentsize;

    for(int i = 0; i<number_sections; i++){
        uint64_t offset = section_offset+i*size_section;
        Elf64_Shdr* section_header = reinterpret_cast<Elf64_Shdr*>(elfFile.data.data()+offset);

        if(section_header->sh_type == SHT_DYNSYM){
            elfFile.dymsym_header_offset = offset;
        }
        else if(section_header->sh_type ==SHT_SYMTAB){
            elfFile.sym_header_offset = offset;
        }
    }

    return true;
}

std::string getSymbolAddress(ELFFile &elfFile, std::string name){
    
}




