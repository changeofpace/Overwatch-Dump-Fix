#include "ow_imports.h"
#include <string>
#include <vector>
#include "fix_dump.h"

////////////////////////////////////////////////////////////////////////////////
// main

// The import address table (DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]) of the
// secret PE Header points to MessageBoxW (changed in 12.13.2016?) which is
// not located at .rdata's base address (abnormal behavior).
//
// This function iterates over the iat, resolves each thunk to the import's
// real virtual address, then patches the iat with the resolved import array.
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] is patched to point to .rdata's base
// address.
BOOL RebuildImports(const REMOTE_PE_HEADER_DATA& HeaderData)
{
    // import thunks to packed code blocks start at .rdata's base address.
    const ULONG_PTR importAddressTable = GetImportAddressTable(HeaderData);
    ULONG_PTR iatThunkArray[512];
    ZeroMemory(iatThunkArray, 512);
    if (!DbgMemRead(importAddressTable, PBYTE(iatThunkArray), 512 * sizeof(ULONG_PTR)))
    {
        PluginLog("RebuildImports:  failed to read import address table at %p.\n", importAddressTable);
        return FALSE;
    }

    // walk the table, resolving all thunks to their real va destination.
    std::vector<ULONG_PTR> unpackedThunkArray;
    for (int i = 0; iatThunkArray[i] > 0; i++)
    {
        for (; iatThunkArray[i] > 0; i++)
            unpackedThunkArray.push_back(UnpackImportThunkBlock(iatThunkArray[i]));
        unpackedThunkArray.push_back(0);
    }
    unpackedThunkArray.push_back(0);

    // replace packed thunks with resolved virtual addresses.
    if (!DbgMemWrite(importAddressTable, PBYTE(unpackedThunkArray.data()), unpackedThunkArray.size() * sizeof(ULONG_PTR)))
    {
        PluginLog("RebuildImports:  failed to write unpacked thunk array to %p.\n", importAddressTable);
        return FALSE;
    }

    // update the header's import address table pointer.
    ULONG_PTR iatdd = HeaderData.baseAddress + HeaderData.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]->VirtualAddress;
    if (!DbgMemWrite(ULONG_PTR(iatdd), PBYTE(&importAddressTable), sizeof(ULONG_PTR)))
    {
        PluginLog("RebuildImports:  failed to patch IAT data directory ptr at %p to %p.\n", iatdd, importAddressTable);
        return FALSE;
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////
// import unpacking

ULONG_PTR GetImportAddressTable(const REMOTE_PE_HEADER_DATA& HeaderData)
{
    return GetSectionVirtualAddressByName(HeaderData, ".rdata");
}

ULONG_PTR UnpackImportThunkBlock(ULONG_PTR BlockBaseAddress)
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

ULONG_PTR UnpackImportThunkDestination(duint Cipher, duint Key, const std::string& Operation)
{
    if (Operation == "xor")
        return Cipher ^ Key;
    else if (Operation == "add")
        return Cipher + Key;
    else if (Operation == "sub")
        return Cipher - Key;
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
