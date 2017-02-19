#include "ow_imports.h"

#include <string>
#include <vector>

#include "fix_dump.h"
#include "memory.h"
#include "plugin.h"

namespace {

const size_t iatMaxEntryCount = 1024;

///////////////////////////////////////////////////////////////////////////////
// import unpacking

duint GetImportAddressTable(const REMOTE_PE_HEADER& HeaderData)
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

duint UnpackImportThunkDestination(duint Cipher, duint Key, const std::string& Operation)
{
    if (Operation == "xor")      return Cipher ^ Key;
    else if (Operation == "add") return Cipher + Key;
    else if (Operation == "sub") return Cipher - Key;
    return 0;
}

duint UnpackImportThunkBlock(duint BlockBaseAddress)
{
    duint ea = BlockBaseAddress;
    DISASM_INSTR disasm;
    DbgDisasmAt(ea, &disasm);
    const duint cipher = disasm.arg[1].value;

    ea += disasm.instr_size;
    DbgDisasmAt(ea, &disasm);
    const std::string op = GetMnemonic(disasm);
    const duint key = disasm.arg[1].value;

    return UnpackImportThunkDestination(cipher, key, op);
}

} // namespace

bool owimports::RebuildImports(const REMOTE_PE_HEADER& HeaderData)
{
    // import thunks to packed code blocks start at .rdata's base address.
    const duint importAddressTable = GetImportAddressTable(HeaderData);
    duint iatThunkArray[iatMaxEntryCount] = {};
    if (!memory::util::RemoteRead(importAddressTable, PVOID(iatThunkArray), iatMaxEntryCount * sizeof(duint)))
    {
        PluginLog("Error: failed to read import address table at %p.\n", importAddressTable);
        return false;
    }

    int importCountDelta = 1;
    // walk the table, resolving all thunks to their real va destination.
    std::vector<duint> unpackedThunkArray;
    for (int i = 0; iatThunkArray[i] > 0; i++)
    {
        for (; iatThunkArray[i] > 0; i++)
            unpackedThunkArray.push_back(UnpackImportThunkBlock(iatThunkArray[i]));
        unpackedThunkArray.push_back(0);
        importCountDelta++;
    }
    unpackedThunkArray.push_back(0);

    const DWORD iatSize = DWORD(unpackedThunkArray.size() * sizeof(duint));

    // replace packed thunks with resolved virtual addresses.
    if (!memory::util::RemoteWrite(importAddressTable, PVOID(unpackedThunkArray.data()), iatSize))
    {
        PluginLog("Error: failed to write unpacked thunk array to %p.\n", importAddressTable);
        return false;
    }

    // update the header's import address table pointer and size.
    const duint iatDDAddress = duint(HeaderData.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]) -
                               duint(HeaderData.dosHeader) +
                               HeaderData.remoteBaseAddress;
    const DWORD iatRVA = DWORD(importAddressTable - HeaderData.remoteBaseAddress);
    if (!memory::util::RemoteWrite(iatDDAddress, PVOID(&iatRVA), sizeof(iatRVA)) ||
        !memory::util::RemoteWrite(iatDDAddress + sizeof(DWORD), PVOID(&iatSize), sizeof(iatSize)))
    {
        PluginLog("Error: failed to patch IAT data directory at %p.\n",iatDDAddress);
        return false;
    }

    PluginLog("restored %d imports at %p.\n",
              unpackedThunkArray.size() - importCountDelta,
              importAddressTable);

    return true;
}
