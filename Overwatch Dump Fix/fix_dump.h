#pragma once

#include <Windows.h>
#include <vector>
#include "plugin.h"
#include "pe_header.h"

namespace fix_dump {
namespace current {

void FixOverwatch();
duint BuildNewOverwatchRegion(const REMOTE_PE_HEADER& OverwatchPEHeader);
bool RestorePEHeader(const REMOTE_PE_HEADER& OverwatchPEHeader, const REMOTE_PE_HEADER& NewRegionPEHeader);
void RestoreSectionProtection(const REMOTE_PE_HEADER& NewRegionPEHeader);
bool NoticeMeScylla(const REMOTE_PE_HEADER& NewRegionPEHeader);

} // namespace current

namespace util {
duint GetOverwatchImageBase();
duint GetSecretPEHeaderBaseAddress();
} // namespace util

// dump fix for previous patches.
namespace winter_2016 {
void FixOverwatch();
BOOL RestorePEHeader();
BOOL FixTextSection(const REMOTE_PE_HEADER& HeaderData);
BOOL GetTextSectionPages(ULONG_PTR TextBaseAddress, ULONG_PTR TextEndAddress, OUT std::vector<MEMORY_BASIC_INFORMATION>& TextPages);
BOOL CombineTextPages(const std::vector<MEMORY_BASIC_INFORMATION>& TextPages, OUT std::vector<MEMORY_BASIC_INFORMATION>& SuspectPages);
BOOL RemoveGarbageCode(ULONG_PTR BaseAddress, SIZE_T RegionSize);
void DumpPages(const std::vector<MEMORY_BASIC_INFORMATION>& Pages);
} // namespace winter_2016

} // namespace fix_dump