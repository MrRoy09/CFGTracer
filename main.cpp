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
#include <queue>
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
    std::map<uint64_t, Block> blocks;
};

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

void exportCFGToDOT(const std::map<uint64_t, Block> &blocks, const std::string &filename)
{
    std::ofstream out(filename + ".dot");
    if (!out.is_open())
    {
        std::cerr << "Failed to open file for CFG output.\n";
        return;
    }

    out << "digraph CFG {\n";
    out << "  node [shape=box fontname=\"Courier\"];\n";

    for (const auto &[addr, block] : blocks)
    {
        std::stringstream label;
        for (const auto &instr : block.instructions)
        {
            label << "0x" << std::hex << instr.address << ": " << instr.mnemonic << " " << instr.op_str << "\\l";
        }

        out << "  \"" << std::hex << block.start_address << "\" [label=\"" << label.str() << "\"];\n";
    }

    for (const auto &[addr, block] : blocks)
    {
        for (uint64_t succ : block.successors)
        {
            out << "  \"" << std::hex << block.start_address << "\" -> \"" << std::hex << succ << "\";\n";
        }
    }

    out << "}\n";
    out.close();
    std::cout << "CFG exported to " << filename << ".dot\n";
}

Block disassemble_block(csh handle, ELFFile &elfFile, uint64_t start_address, std::set<uint64_t> &visited_instructions);
void disassemble_function_recursive(csh handle, ELFFile &elfFile, Function &function, uint64_t start_address);

void disassemble_symbols(ELFFile &elfFile, std::vector<Symbol> &symbols)
{
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        std::cerr << "Failed to initialize Capstone handle\n";
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (auto &symbol : symbols)
    {
        if (!symbol.executable)
        {
            continue;
        }

        Function function;
        function.name = symbol.name;
        function.start_address = symbol.address;

        disassemble_function_recursive(handle, elfFile, function, symbol.address);

        printf("\nDisassembled %s - Found %zu blocks\n", symbol.name.c_str(), function.blocks.size());

        exportCFGToDOT(function.blocks, function.name+".dot");
    }

    cs_close(&handle);
}

void disassemble_function_recursive(csh handle, ELFFile &elfFile, Function &function, uint64_t start_address)
{
    std::set<uint64_t> visited_instructions;
    std::set<uint64_t> pending_addresses;
    std::set<uint64_t> processed_block_starts;

    pending_addresses.insert(start_address);

    while (!pending_addresses.empty())
    {
        uint64_t current_address = *pending_addresses.begin();
        pending_addresses.erase(pending_addresses.begin());

        if (processed_block_starts.count(current_address) > 0)
        {
            continue;
        }

        processed_block_starts.insert(current_address);

        bool found_in_block = false;
        for (const auto &[block_addr, block] : function.blocks)
        {
            if (current_address >= block.start_address && current_address < block.end_address)
            {
                found_in_block = true;
                break;
            }
        }

        if (found_in_block)
        {
            continue;
        }

        Block block = disassemble_block(handle, elfFile, current_address, visited_instructions);

        if (!block.instructions.empty())
        {
            function.blocks[block.start_address] = block;

            for (uint64_t succ : block.successors)
            {
                if (function.blocks.count(succ) > 0)
                {
                    function.blocks[succ].predecessors.insert(block.start_address);
                }

                pending_addresses.insert(succ);
            }
        }
    }

    for (auto &[addr, block] : function.blocks)
    {
        for (uint64_t succ : block.successors)
        {
            if (function.blocks.count(succ) > 0)
            {
                function.blocks[succ].predecessors.insert(block.start_address);
            }
        }
    }
}

Block disassemble_block(csh handle, ELFFile &elfFile, uint64_t start_address, std::set<uint64_t> &visited_instructions)
{
    Block block;
    block.start_address = start_address;
    uint64_t current_offset = start_address;
    cs_insn *insn = nullptr;

    while (true)
    {
        if (visited_instructions.count(current_offset))
        {
            block.end_address = current_offset;
            return block;
        }

        size_t count = cs_disasm(handle, elfFile.data.data() + current_offset,
                                 elfFile.data.size() - current_offset, current_offset, 1, &insn);

        if (count == 0)
        {
            std::cerr << "Disassembly error at: 0x" << std::hex << current_offset << std::endl;
            if (!block.instructions.empty())
            {
                block.end_address = current_offset;
            }
            return block;
        }

        Instruction instr;
        instr.address = insn[0].address;
        instr.mnemonic = insn[0].mnemonic;
        instr.op_str = insn[0].op_str;
        instr.details = insn[0].detail;
        instr.id = insn[0].id;

        block.instructions.push_back(instr);

        visited_instructions.insert(current_offset);

        uint64_t next_address = current_offset + insn[0].size;

        bool is_control_flow = false;
        if (instr.details && instr.details->groups_count > 0)
        {
            for (int i = 0; i < instr.details->groups_count; ++i)
            {
                uint8_t group = instr.details->groups[i];
                if (group == CS_GRP_JUMP || group == CS_GRP_CALL || group == CS_GRP_RET || group == CS_GRP_INT || instr.mnemonic == "hlt")
                {
                    is_control_flow = true;

                    if (instr.mnemonic == "jmp" && instr.details->x86.op_count > 0)
                    {
                        cs_x86_op op = instr.details->x86.operands[0];
                        if (op.type == X86_OP_IMM)
                        {
                            block.successors.insert(op.imm);
                        }
                    }
                    else if (group == CS_GRP_JUMP && instr.details->x86.op_count > 0)
                    {
                        cs_x86_op op = instr.details->x86.operands[0];
                        if (op.type == X86_OP_IMM)
                        {
                            block.successors.insert(op.imm);
                            block.successors.insert(next_address);
                        }
                    }
                    else if (group == CS_GRP_CALL && instr.details->x86.op_count > 0)
                    {
                        block.successors.insert(next_address);
                        is_control_flow = true;
                    }
                    else if (group == CS_GRP_RET)
                    {
                        block.isReturn = true;
                    }
                    else if (instr.mnemonic == "hlt")
                    {
                        block.isReturn = true;
                    }
                    else if (group == CS_GRP_INT)
                    {
                        is_control_flow = false;
                    }
                }
            }
        }

        if (is_control_flow)
        {
            block.end_address = next_address;
            cs_free(insn, count);
            return block;
        }

        current_offset = next_address;
        cs_free(insn, count);
    }

    block.end_address = current_offset;
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
    std::vector<Symbol> symbols = parseSymbolTable(elfFile);
    disassemble_symbols(elfFile, symbols);
    return 0;
}