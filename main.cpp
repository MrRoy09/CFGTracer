#include <fstream>
#include <vector>
#include <cstdint>
#include <inttypes.h>
#include <elf.h>
#include <iostream>
#include <capstone/capstone.h>
#include <set>

struct ELFFile
{
    std::vector<uint8_t> data;
    uint64_t entry_offset;
};

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

bool check_visited(uint64_t offset, std::set<uint64_t> &visited)
{
    if (visited.empty())
        return false;
    return visited.count(offset);
}

void printBytes(ELFFile &elfFile, uint64_t offset, size_t count)
{
    printf("hello\n");
    for (size_t i = 0; i < count; i++)
    {
        printf("%02X ", elfFile.data[offset + i]);
    }
}

void disassemble(ELFFile &elfFile)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        printf("Failed to initialize capstone handle\n");

    std::vector<uint64_t> worklist = {elfFile.entry_offset};
    std::set<uint64_t> visited;

    while (!worklist.empty())
    {
        uint64_t address = worklist.back();
        worklist.pop_back();
        count = cs_disasm(handle, elfFile.data.data() + address, elfFile.data.size(), address, 1, &insn);

        if (count > 0)
        {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,insn[0].op_str);
            worklist.emplace_back(address + insn[0].size);
            cs_free(insn, count);
        }
        else
        {
            printf("ERROR: Failed to disassemble given code at offset 0x%lx\n", address);
            address++;
        }
    }
    cs_close(&handle);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <ELF File>" << std::endl;
        return 1;
    }

    ELFFile elfFile;
    if (!loadELF(argv[1], elfFile))
    {
        return 1;
    }

    if (!getEntryOffset(elfFile))
    {
        return 1;
    }

    std::cout << "Entry offset: 0x" << std::hex << elfFile.entry_offset << std::endl;
    disassemble(elfFile);
    return 0;
}
