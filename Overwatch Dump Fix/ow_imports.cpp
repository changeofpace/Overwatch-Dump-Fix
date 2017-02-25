#include "ow_imports.h"

#include <string>
#include <vector>

#include "fix_dump.h"
#include "memory.h"
#include "plugin.h"

namespace {

const size_t iatMaxEntryCount = 2048;

///////////////////////////////////////////////////////////////////////////////
// import unpacking

SIZE_T GetImportAddressTable(const REMOTE_PE_HEADER& HeaderData)
{
    PIMAGE_SECTION_HEADER rdata = GetPeSectionByName(HeaderData, ".rdata");
    return rdata != nullptr ? HeaderData.remoteBaseAddress + rdata->VirtualAddress : 0;
}

std::string GetMnemonic(const DISASM_INSTR& Disasm)
{
    int i = 0;
    while (Disasm.instruction[i] != ' ') i++;
    return std::string(Disasm.instruction, Disasm.instruction + i);
}

SIZE_T UnpackImportThunkDestination(SIZE_T Cipher, SIZE_T Key, const std::string& Operation)
{
    if (Operation == "xor")      return Cipher ^ Key;
    else if (Operation == "add") return Cipher + Key;
    else if (Operation == "sub") return Cipher - Key;
    return 0;
}

SIZE_T UnpackImportThunkBlock(SIZE_T BlockBaseAddress)
{
    SIZE_T ea = BlockBaseAddress;
    DISASM_INSTR disasm;
    DbgDisasmAt(ea, &disasm);
    const SIZE_T cipher = disasm.arg[1].value;

    ea += disasm.instr_size;
    DbgDisasmAt(ea, &disasm);
    const std::string op = GetMnemonic(disasm);
    const SIZE_T key = disasm.arg[1].value;

    return UnpackImportThunkDestination(cipher, key, op);
}

} // namespace

bool owimports::RebuildImports(const REMOTE_PE_HEADER& HeaderData)
{
    // import thunks to packed code blocks start at .rdata's base address.
    const SIZE_T importAddressTable = GetImportAddressTable(HeaderData);
    SIZE_T iatThunkArray[iatMaxEntryCount] = {};
    if (!memory::util::RemoteRead(importAddressTable, PVOID(iatThunkArray), iatMaxEntryCount * sizeof(SIZE_T)))
    {
        PluginLog("Error: failed to read import address table at %p.\n", importAddressTable);
        return false;
    }

    int importCountDelta = 1;
    // walk the table, resolving all thunks to their real va destination.
    std::vector<SIZE_T> unpackedThunkArray;
    for (int i = 0; iatThunkArray[i] > 0; i++)
    {
        for (; iatThunkArray[i] > 0; i++)
            unpackedThunkArray.push_back(UnpackImportThunkBlock(iatThunkArray[i]));
        unpackedThunkArray.push_back(0);
        importCountDelta++;
    }
    unpackedThunkArray.push_back(0);

    const DWORD iatSize = DWORD(unpackedThunkArray.size() * sizeof(SIZE_T));

    // replace packed thunks with resolved virtual addresses.
    if (!memory::util::RemoteWrite(importAddressTable, PVOID(unpackedThunkArray.data()), iatSize))
    {
        PluginLog("Error: failed to write unpacked thunk array to %p.\n", importAddressTable);
        return false;
    }

    // update the header's import address table pointer and size.
    const SIZE_T iatDDAddress = SIZE_T(HeaderData.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]) -
                                SIZE_T(HeaderData.dosHeader) +
                                HeaderData.remoteBaseAddress;
    const DWORD iatRVA = DWORD(importAddressTable - HeaderData.remoteBaseAddress);
    if (!memory::util::RemoteWrite(iatDDAddress, PVOID(&iatRVA), sizeof(iatRVA)) ||
        !memory::util::RemoteWrite(iatDDAddress + sizeof(DWORD), PVOID(&iatSize), sizeof(iatSize)))
    {
        PluginLog("Error: failed to patch IAT data directory at %p.\n",iatDDAddress);
        return false;
    }

    PluginLog("Restored %d imports at %p.\n",
              unpackedThunkArray.size() - importCountDelta,
              importAddressTable);

    return true;
}
