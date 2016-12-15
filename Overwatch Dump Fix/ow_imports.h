#pragma once

#include <Windows.h>
#include "plugin.h"
#include "pe_header.h"

////////////////////////////////////////////////////////////////////////////////
// main

BOOL RebuildImports(const REMOTE_PE_HEADER_DATA& HeaderData);

////////////////////////////////////////////////////////////////////////////////
// import unpacking

ULONG_PTR GetImportAddressTable(const REMOTE_PE_HEADER_DATA& HeaderData);
ULONG_PTR UnpackImportThunkBlock(ULONG_PTR BlockBaseAddress);
ULONG_PTR UnpackImportThunkDestination(duint Cipher, duint Key, const std::string& Operation);

////////////////////////////////////////////////////////////////////////////////
// utils

std::string GetMnemonic(const DISASM_INSTR& Disasm);
