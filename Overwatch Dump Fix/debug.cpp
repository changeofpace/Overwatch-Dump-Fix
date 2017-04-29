#include "debug.h"

#include "plugin.h"

#include "pluginsdk/capstone/capstone.h"

void plugindbg::DumpMemoryBasicInformation(const MEMORY_BASIC_INFORMATION& Mbi)
{
    plog(DELIM_MAJOR);
    plog("MEMORY_BASIC_INFORMATION\n");
    plog(DELIM_MAJOR);
    plog("    BaseAddress:         %p\n", Mbi.BaseAddress);
    plog("    AllocationBase:      %p\n", Mbi.AllocationBase);
    plog("    AllocationProtect:   %016X\n", Mbi.AllocationProtect);
    plog("    RegionSize:          %016X\n", Mbi.RegionSize);
    plog("    State:               %16X\n", Mbi.State);
    plog("    Protect:             %16X\n", Mbi.Protect);
    plog("    Type:                %16X\n", Mbi.Type);
}

void plugindbg::DumpMemoryBasicInformationShort(const MEMORY_BASIC_INFORMATION& Mbi)
{
    plog("base: %p    size: %16llX    prot: %8X   init prot: %8X\n",
         Mbi.BaseAddress, Mbi.RegionSize, Mbi.Protect, Mbi.AllocationProtect);
}

void plugindbg::DumpCapstoneInsn(csh hCapstone, const cs_insn * Insn, size_t RemoteAddress)
{
    plog(DELIM_MAJOR);
    plog("cs_insn\n");
    plog(DELIM_MAJOR);
    plog("id:         %X (%u)\n", Insn->id, Insn->id);
    if (RemoteAddress) {
        plog("local  address:    %p\n", Insn->address);
        plog("remote address:    %p\n", RemoteAddress);
    } else {
        plog("address:    %p\n", Insn->address);
    }
    plog("size:       %X (%u)\n", Insn->size, Insn->size);
    plog("mnemonic:   %s\n", Insn->mnemonic);
    plog("op_str:     %s\n", Insn->op_str);
    plog("bytes:      ");
    for (int i = 0; i < 16; i++)
        plog("%02X ", Insn->bytes[i]);
    plog("\n");
    if (Insn->detail == nullptr) {
        plog("detail is null.\n");
        return;
    }
    plog(DELIM_MINOR);
    plog("opcode:     %X %X %X %X\n", Insn->detail->x86.opcode[0],
        Insn->detail->x86.opcode[1],
        Insn->detail->x86.opcode[2],
        Insn->detail->x86.opcode[3]);
    plog("rex:        %X (%u)\n", Insn->detail->x86.rex, Insn->detail->x86.rex);
    plog("addr_size:  %X (%u)\n", Insn->detail->x86.addr_size, Insn->detail->x86.addr_size);
    plog("modrm:      %X (%u)\n", Insn->detail->x86.modrm, Insn->detail->x86.modrm);
    plog("disp:       %X (%d)\n", Insn->detail->x86.disp, Insn->detail->x86.disp);
    plog("sib:        %X (%u)\n", Insn->detail->x86.sib, Insn->detail->x86.sib);
    plog("sib_index:  %X (%d)\n", Insn->detail->x86.sib_index, Insn->detail->x86.sib_index);
    plog("sib_scale:  %X (%d)\n", Insn->detail->x86.sib_scale, Insn->detail->x86.sib_scale);
    plog("sib_base:   %X (%d)\n", Insn->detail->x86.sib_base, Insn->detail->x86.sib_base);
    plog("x86_xop_cc: %X (%d)\n", Insn->detail->x86.xop_cc, Insn->detail->x86.xop_cc);
    plog("sse_cc:     %X (%d)\n", Insn->detail->x86.sse_cc, Insn->detail->x86.sse_cc);
    plog("sib_base:   %X (%d)\n", Insn->detail->x86.avx_cc, Insn->detail->x86.avx_cc);
    plog("op_count:   %X (%u)\n", Insn->detail->x86.op_count, Insn->detail->x86.op_count);

    for (int i = 0; i < Insn->detail->x86.op_count; i++) {
        const cs_x86_op & operand = Insn->detail->x86.operands[i];
        plog(DELIM_MINOR);
        plog("    type:     %X (%d)\n", operand.type, operand.type);
        plog("    size:     %X (%u)\n", operand.size, operand.size);
        switch (operand.type)
        {
        case X86_OP_INVALID:
            plog("    op_type:  INVALID\n");
            break;
        case X86_OP_REG:
            plog("    op_type:  REG\n");
            plog("    reg:      %s %X (%d)\n", cs_reg_name(hCapstone, operand.reg),
                 operand.reg, operand.reg);
            break;
        case X86_OP_IMM:
            plog("    op_type:  IMM\n");
            plog("    imm:      %llX (%lld)\n", operand.imm, operand.imm);
            break;
        case X86_OP_MEM:
            plog("    op_type:  MEM\n");
            plog("    mem:      %X (%d)\n", operand.mem, operand.mem);
            break;
        }
    }
}
