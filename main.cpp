#include <fstream>
#include <vector>
#include <cstdint>
#include <inttypes.h>
#include <elf.h>
#include <iostream>
#include <capstone/capstone.h>
#include <set>
#include "elf_parser.h"

struct Instruction
{
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
    cs_detail *details;
};

struct Block
{
    uint64_t start_address;
    uint64_t end_address;
    std::vector<Instruction> instructions;
    std::set<uint64_t> successors;
    std::set<uint64_t> predecessors;
    bool isReturn;
};

struct Function
{
    std::string name;
    uint64_t start_address;
    uint64_t end_address;
    std::vector<Block> blocks;
};

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

void printInstructions(const std::vector<Instruction> &instructions)
{
    std::cout << "\nDisassembled Instructions:\n";
    std::cout << "---------------------------------------------\n";
    for (const auto &instr : instructions)
    {
        printf("0x%08" PRIx64 ": %-8s %s\n", instr.address, instr.mnemonic.c_str(), instr.op_str.c_str());
    }
    std::cout << "---------------------------------------------\n";
}

void disassemble_function(csh handle, ELFFile &elfFile, uint64_t address, std::set<uint64_t> &visited, std::vector<Block> &blocks);

void disassemble(ELFFile &elfFile)
{
    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        printf("Failed to initialize capstone handle\n");
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    std::vector<Block> blocks;
    std::set<uint64_t> visited;
    disassemble_function(handle, elfFile, elfFile.entry_offset, visited, blocks);
    cs_close(&handle);
}

void disassemble_function(csh handle, ELFFile &elfFile, uint64_t address, std::set<uint64_t> &visited, std::vector<Block> &blocks)
{
    if (visited.find(address) != visited.end())
    {
        return;
    }
    visited.insert(address);
    Function function;
    function.start_address = address;

    while (true)
    {
        std::vector<Instruction> instructions;
        Block block = disassemble_block(handle, elfFile, address, visited, instructions);
        if(block.isReturn){
            break;
        }
        address = block.end_address;
    }
}

Block disassemble_block(csh handle, ELFFile &elfFile, uint64_t address, std::set<uint64_t> visited, std::vector<Instruction> &instructions)
{
    if (visited.find(address) != visited.end())
    {
        return {};
    }

    visited.insert(address);
    Block block;
    block.start_address = address;
    cs_insn *insn;

    while (true)
    {
        size_t count = cs_disasm(handle, elfFile.data.data() + address, elfFile.data.size() - address, address, 1, &insn);

        if (count == 0)
        {
            std::cerr << "Disassembly error at: 0x" << std::hex << address << std::endl;
            break;
        }

        Instruction instr;
        instr.address = insn[0].address;
        instr.mnemonic = insn[0].mnemonic;
        instr.op_str = insn[0].op_str;
        instr.details = insn[0].detail;

        block.instructions.push_back(instr);
        uint64_t next_address = address + insn[0].size;

        if (instr.mnemonic == "jmp")
        {
            cs_x86_op op = instr.details->x86.operands[0];
            if (op.type != X86_OP_IMM)
            {
                continue;
            }
            block.end_address = next_address;
            block.isReturn = 0;
            return block;
        }

        if (instr.mnemonic == "ret")
        {
            block.end_address = next_address;
            block.isReturn = 1;
            return block;
        }
        address = next_address;
    }
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
