#include "ow_imports.h"

#include <string>
#include <vector>

#include "fix_dump.h"
#include "memory.h"
#include "plugin.h"

static const SIZE_T iatMaxEntryCount = 2048;

static SIZE_T GetImportAddressTable(const REMOTE_PE_HEADER& HeaderData)
{
    PIMAGE_SECTION_HEADER rdata = GetPeSectionByName(HeaderData, ".rdata");
    return rdata != nullptr ? HeaderData.remoteBaseAddress + rdata->VirtualAddress : 0;
}

owimports::ImportUnpacker::~ImportUnpacker()
{
    if (hCapstone) {
        cs_close(&hCapstone);
        cs_free(insn, 1);
    }
}

bool owimports::ImportUnpacker::initialize()
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &hCapstone) != CS_ERR_OK)
        return false;
    if (cs_option(hCapstone, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
        return false;
    insn = cs_malloc(hCapstone);
    return true;
}

SIZE_T owimports::ImportUnpacker::resolve(size_t ThunkBase)
{
    const SIZE_T regionBase = memory::util::AlignToAllocationGranularity(ThunkBase);
    const SIZE_T blockSize = 0x60;
    SIZE_T import = 0;
    SIZE_T ea = ThunkBase;

    for (;;) {
        const SIZE_T readSize = min(blockSize, regionBase + PAGE_SIZE - ea);
        unsigned char codeBlock[blockSize];
        memset(codeBlock, 0, blockSize);

        if (!memory::util::RemoteRead(ea, codeBlock, readSize)) {
            pluginLog("Error: failed to read 0x%llX bytes at %p.\n", readSize, ea);
            return 0;
        }

        if (resolveBlock(codeBlock, readSize, ea, import))
            break;
    }

    return import;
}

bool owimports::ImportUnpacker::resolveBlock(const unsigned char * CodeBuf, SIZE_T CodeSize, SIZE_T & EA, SIZE_T & Import)
{
    while (cs_disasm_iter(hCapstone, &CodeBuf, &CodeSize, &EA, insn)) {
        switch (insn->id)
        {
        case X86_INS_MOVABS:
        {
            Import = insn->detail->x86.operands[insn->detail->x86.op_count - 1].imm;
            break;
        }
        case X86_INS_ADD:
        {
            Import += insn->detail->x86.operands[insn->detail->x86.op_count - 1].imm;
            break;
        }
        case X86_INS_SUB:
        {
            Import -= insn->detail->x86.operands[insn->detail->x86.op_count - 1].imm;
            break;
        }
        case X86_INS_XOR:
        {
            Import ^= insn->detail->x86.operands[insn->detail->x86.op_count - 1].imm;
            break;
        }
        // jmp rax = end of block, the import should be resolved.
        // jmp [IMMEDIATE] = continue resolving the thunk at a new block base, inside the current region.
        case X86_INS_JMP:
        {
            if (insn->detail->x86.operands[insn->detail->x86.op_count - 1].type == X86_OP_REG) {
                return true;
            } else {
                EA = insn->detail->x86.operands[insn->detail->x86.op_count - 1].imm;
                return false;
            }
            break;
        }
        default:
        {
            pluginLog("Error: encountered unhandled instruction opcode while unpacking import at %p.\n", EA);
            EA = 0;
            return false;
        }
        }
    }
    return false;
}

bool owimports::RebuildImports(const REMOTE_PE_HEADER& HeaderData)
{
    ImportUnpacker unpacker;
    if (!unpacker.initialize()) {
        pluginLog("Error: failed to initialize import unpacker.\n");
        return false;
    }

    // import thunks to packed code blocks start at .rdata's base address.
    const SIZE_T importAddressTable = GetImportAddressTable(HeaderData);
    SIZE_T iatThunkArray[iatMaxEntryCount] = {};
    if (!memory::util::RemoteRead(importAddressTable, PVOID(iatThunkArray),
                                  iatMaxEntryCount * sizeof(SIZE_T))) {
        pluginLog("Error: failed to read import address table at %p.\n",
                  importAddressTable);
        return false;
    }

    int importCountDelta = 1;
    // walk the table, resolving all thunks to their real va destination.
    std::vector<SIZE_T> unpackedThunkArray;
    for (int i = 0; iatThunkArray[i] > 0; i++) {
        for (/**/; iatThunkArray[i] > 0; i++)
            unpackedThunkArray.push_back(unpacker.resolve(iatThunkArray[i]));
        unpackedThunkArray.push_back(0);
        importCountDelta++;
    }
    unpackedThunkArray.push_back(0);

    pluginLog("Found import address table at %p.\n", importAddressTable);

    const DWORD iatSize = DWORD(unpackedThunkArray.size() * sizeof(SIZE_T));

    // replace packed thunks with resolved virtual addresses.
    if (!memory::util::RemoteWrite(importAddressTable,
                                   PVOID(unpackedThunkArray.data()), iatSize)) {
        pluginLog("Error: failed to write unpacked thunk array to %p.\n",
                  importAddressTable);
        return false;
    }

    // update the header's import address table pointer and size.
    const SIZE_T iatDDAddress = SIZE_T(HeaderData.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]) -
                                SIZE_T(HeaderData.dosHeader) +
                                HeaderData.remoteBaseAddress;
    const DWORD iatRVA = DWORD(importAddressTable - HeaderData.remoteBaseAddress);

    if (!memory::util::RemoteWrite(iatDDAddress, PVOID(&iatRVA), sizeof(iatRVA)) ||
        !memory::util::RemoteWrite(iatDDAddress + sizeof(DWORD), PVOID(&iatSize), sizeof(iatSize))) {
        pluginLog("Error: failed to patch IAT data directory at %p.\n", iatDDAddress);
        return false;
    }

    pluginLog("Restored %d imports at %p.\n",
              unpackedThunkArray.size() - importCountDelta, importAddressTable);

    return true;
}
