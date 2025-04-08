#include <fstream>
#include <vector>
#include <cstdint>
#include <inttypes.h>
#include <elf.h>
#include <iostream>
#include <capstone/capstone.h>
#include <set>
#include <map>
#include <sstream>
#include "elf_parser.h"

struct Instruction
{
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
    cs_detail *details;
    uint32_t id;
};

struct Block
{
    uint64_t start_address;
    uint64_t end_address;
    std::vector<Instruction> instructions;
    std::set<uint64_t> successors;
    std::set<uint64_t> predecessors;
    bool isReturn = false;
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
    return visited.count(offset) > 0;
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

void exportCFGToDOT(const std::vector<Block> &blocks, const std::string &filename)
{
    std::ofstream out(filename);
    if (!out.is_open())
    {
        std::cerr << "Failed to open file for CFG output.\n";
        return;
    }

    out << "digraph CFG {\n";
    out << "  node [shape=box fontname=\"Courier\"];\n";

    for (const auto &block : blocks)
    {
        std::stringstream label;
        // label << "0x" << std::hex << block.start_address << ":\\l";
        for (const auto &instr : block.instructions)
        {
            label << "0x" << std::hex << instr.address << ": " << instr.mnemonic << " " << instr.op_str << "\\l";
        }

        out << "  \"" << std::hex << block.start_address << "\" [label=\"" << label.str() << "\"];\n";
    }

    for (const auto &block : blocks)
    {
        for (uint64_t succ : block.successors)
        {
            out << "  \"" << std::hex << block.start_address << "\" -> \"" << std::hex << succ << "\";\n";
        }
    }

    out << "}\n";
    out.close();
}

Block disassemble_block(csh handle, ELFFile &elfFile, std::map<uint64_t, uint8_t> &visited);
void disassemble_function(csh handle, ELFFile &elfFile, std::vector<Block> &blocks);

void disassemble_symbols(ELFFile &elfFile, std::vector<Symbol> &symbols)
{
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        std::cerr << "Failed to initialize Capstone handle\n";
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (auto &i : symbols)
    {
        if (!i.executable)
        {
            continue;
        }
        elfFile.current_offset = i.address;
        std::vector<Block> blocks;
        disassemble_function(handle, elfFile, blocks);
        printf("\nDisassembled %s\n", i.name.c_str());
        if (i.name == "main")
        {
            exportCFGToDOT(blocks, "main_cfg");
        }
    }

    cs_close(&handle);
}

void disassemble_function(csh handle, ELFFile &elfFile, std::vector<Block> &blocks)
{

    while (true)
    {
        std::map<uint64_t, uint8_t> visited;
        Block block = disassemble_block(handle, elfFile, visited);
        if (block.instructions.empty())
            break;

        blocks.push_back(block);
        if (block.isReturn)
            break;

        elfFile.current_offset = block.end_address;
    }
}

Block disassemble_block(csh handle, ELFFile &elfFile, std::map<uint64_t, uint8_t> &visited)
{
    Block block;
    block.start_address = elfFile.current_offset;
    cs_insn *insn = nullptr;

    while (true)
    {
        if (visited.count(elfFile.current_offset))
        {
            elfFile.current_offset += visited.find(elfFile.current_offset)->second;
            continue;
        }

        size_t count = cs_disasm(handle, elfFile.data.data() + elfFile.current_offset,
                                 elfFile.data.size() - elfFile.current_offset, elfFile.current_offset, 1, &insn);

        if (count == 0)
        {
            std::cerr << "Disassembly error at: 0x" << std::hex << elfFile.current_offset << std::endl;
            break;
        }

        Instruction instr;
        instr.address = insn[0].address;
        instr.mnemonic = insn[0].mnemonic;
        instr.op_str = insn[0].op_str;
        instr.details = insn[0].detail;
        instr.id = insn[0].id;

        block.instructions.push_back(instr);
        uint64_t next_address = elfFile.current_offset + insn[0].size;
        visited.insert({elfFile.current_offset, insn[0].size});

        if (instr.details && instr.details->groups_count > 0)
        {
            for (int i = 0; i < instr.details->groups_count; ++i)
            {
                uint8_t group = instr.details->groups[i];
                if (group == CS_GRP_JUMP || group == CS_GRP_CALL || group == CS_GRP_RET || group == CS_GRP_INT)
                {
                    if (group == CS_GRP_JUMP && instr.details->x86.op_count > 0)
                    {
                        cs_x86_op op = instr.details->x86.operands[0];
                        if (op.type == X86_OP_IMM)
                        {
                            block.successors.insert(op.imm);
                        }
                    }

                    if (instr.mnemonic != "jmp")
                    {
                        block.successors.insert(elfFile.current_offset + insn[0].size);
                    }
                    block.end_address = next_address;
                    block.isReturn = (group == CS_GRP_RET || instr.id == X86_INS_HLT);
                    cs_free(insn, count);
                    return block;
                }
            }
        }

        elfFile.current_offset = next_address;
        cs_free(insn, count);
    }

    block.end_address = elfFile.current_offset;
    return block;
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
        std::cerr << "Failed to load ELF file.\n";
        return 1;
    }

    if (!getEntryOffset(elfFile))
    {
        std::cerr << "Failed to get entry offset.\n";
        return 1;
    }

    std::cout << "Entry offset: 0x" << std::hex << elfFile.entry_offset << std::endl;
    elfFile.current_offset = elfFile.entry_offset;
    std::vector<Symbol> symbols = parseSymbolTable(elfFile);
    disassemble_symbols(elfFile, symbols);
    return 0;
}
