#pragma once

#include <Windows.h>
#include <string>
#include "plugin.h"
#include "pe_header.h"

////////////////////////////////////////////////////////////////////////////////
// types

struct ScyllaIATInfo
{
    duint oep;
    duint va;
    DWORD size;

    ScyllaIATInfo() {}
    ScyllaIATInfo(duint O, duint V, DWORD S) : oep(O), va(V), size(S) {}
};

////////////////////////////////////////////////////////////////////////////////
// main

bool RebuildImports(const REMOTE_PE_HEADER& HeaderData);
ScyllaIATInfo GetScyllaInfo();

////////////////////////////////////////////////////////////////////////////////
// import unpacking

duint GetImportAddressTable(const REMOTE_PE_HEADER& HeaderData);
duint UnpackImportThunkBlock(duint BlockBaseAddress);
duint UnpackImportThunkDestination(duint Cipher, duint Key, const std::string& Operation);

////////////////////////////////////////////////////////////////////////////////
// utils

std::string GetMnemonic(const DISASM_INSTR& Disasm);
