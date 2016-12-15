#pragma once

#include <Windows.h>
#include <vector>
#include "plugin.h"
#include "pe_header.h"

////////////////////////////////////////////////////////////////////////////////
// constants

// plugin exported command
const char* const cmdOverwatchDumpFix = "OverwatchDumpFix";

////////////////////////////////////////////////////////////////////////////////
// main

VOID FixOverwatch();
BOOL RestorePEHeader();
BOOL FixTextSection(const REMOTE_PE_HEADER_DATA& HeaderData);

////////////////////////////////////////////////////////////////////////////////
// utils

BOOL GetTextSectionPages(ULONG_PTR TextBaseAddress, ULONG_PTR TextEndAddress, OUT std::vector<MEMORY_BASIC_INFORMATION>& TextPages);
BOOL CombineTextPages(const std::vector<MEMORY_BASIC_INFORMATION>& TextPages, OUT std::vector<MEMORY_BASIC_INFORMATION>& SuspectPages);
BOOL RemoveGarbageCode(ULONG_PTR BaseAddress, SIZE_T RegionSize);

////////////////////////////////////////////////////////////////////////////////
// address getters

ULONG_PTR GetOverwatchImageBase();
ULONG_PTR GetSecretPEHeaderBaseAddress();

////////////////////////////////////////////////////////////////////////////////
// debug

VOID DumpPages(const std::vector<MEMORY_BASIC_INFORMATION>& Pages);