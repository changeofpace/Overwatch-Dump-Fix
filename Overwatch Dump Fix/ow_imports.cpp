#include "ow_imports.h"
#include <vector>
#include "fix_dump.h"
#include "memory_util.h"

namespace {
const size_t iatMaxEntryCount = 1024;
ScyllaIATInfo scyllaInfo;
}

////////////////////////////////////////////////////////////////////////////////
// main

// This function iterates over the iat, resolves each thunk to the import's
// real virtual address, then patches the iat with the resolved import array.
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] is patched to point to .rdata's base
// address.
bool RebuildImports(const REMOTE_PE_HEADER& HeaderData)
{
    // import thunks to packed code blocks start at .rdata's base address.
    const duint importAddressTable = GetImportAddressTable(HeaderData);
    duint iatThunkArray[iatMaxEntryCount] = {};
    if (!memutil::RemoteRead(importAddressTable, PBYTE(iatThunkArray), iatMaxEntryCount * sizeof(duint)))
    {
        PluginLog("RebuildImports: failed to read import address table at %p.\n", importAddressTable);
        return false;
    }

    // walk the table, resolving all thunks to their real va destination.
    std::vector<duint> unpackedThunkArray;
    for (int i = 0; iatThunkArray[i] > 0; i++)
    {
        for (; iatThunkArray[i] > 0; i++)
            unpackedThunkArray.push_back(UnpackImportThunkBlock(iatThunkArray[i]));
        unpackedThunkArray.push_back(0);
    }
    unpackedThunkArray.push_back(0);

    const DWORD iatSize = DWORD(unpackedThunkArray.size() * sizeof(duint));

    // replace packed thunks with resolved virtual addresses.
    if (!memutil::RemoteWrite(importAddressTable, PBYTE(unpackedThunkArray.data()), iatSize))
    {
        PluginLog("RebuildImports: failed to write unpacked thunk array to %p.\n", importAddressTable);
        return false;
    }

    // update the header's import address table pointer and size.
    const duint iatDDAddress = duint(HeaderData.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]) - duint(HeaderData.dosHeader) + HeaderData.remoteBaseAddress;
    const DWORD iatRVA = DWORD(importAddressTable - HeaderData.remoteBaseAddress);
    if (!memutil::RemoteWrite(iatDDAddress, PVOID(&iatRVA), sizeof(iatRVA)) ||
        !memutil::RemoteWrite(iatDDAddress + sizeof(DWORD), PVOID(&iatSize), sizeof(iatSize)))
    {
        PluginLog("RebuildImports: failed to patch IAT data directory at %p.\n", iatDDAddress);
        return false;
    }

    // imports successfully rebuilt. Set the values to use in Scylla's IAT Info 'box'.
    const duint oep = HeaderData.remoteBaseAddress + HeaderData.optionalHeader->AddressOfEntryPoint;
    scyllaInfo = ScyllaIATInfo(oep, importAddressTable, iatSize);

    return true;
}

ScyllaIATInfo GetScyllaInfo()
{
    return scyllaInfo;
}

////////////////////////////////////////////////////////////////////////////////
// import unpacking

duint GetImportAddressTable(const REMOTE_PE_HEADER& HeaderData)
{
    PIMAGE_SECTION_HEADER rdata = GetSectionByName(HeaderData, ".rdata");
    return rdata != nullptr ? HeaderData.remoteBaseAddress + rdata->VirtualAddress : 0;
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

duint UnpackImportThunkDestination(duint Cipher, duint Key, const std::string& Operation)
{
    if      (Operation == "xor") return Cipher ^ Key;
    else if (Operation == "add") return Cipher + Key;
    else if (Operation == "sub") return Cipher - Key;
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
// utils

std::string GetMnemonic(const DISASM_INSTR& Disasm)
{
    int i = 0;
    while (Disasm.instruction[i] != ' ') i++;
    return std::string(Disasm.instruction, Disasm.instruction + i);
}
