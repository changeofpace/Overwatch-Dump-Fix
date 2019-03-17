#pragma once

#include <Windows.h>

#include "pe_header.h"
#include "plugin.h"

namespace fixdump {
namespace current {

bool FixOverwatch();
BOOL GetOverwatchImageSize(HANDLE hProcess, PULONG pcbImageSize);
bool GetOverwatchPeHeader(BUFFERED_PE_HEADER& PeHeader);
// Individual field fixups.
void FixPeHeader(BUFFERED_PE_HEADER& PeHeader);
// Patch Overwatch.exe's PE Header.
BOOL RestorePeHeader(BUFFERED_PE_HEADER& PeHeader);
// Split the pe header, .text, and .rdata regions by setting page protection.
bool SplitSections(const REMOTE_PE_HEADER& PeHeader);

} // namespace current

#if 0
namespace archive {
SIZE_T GetSecretPEHeaderBaseAddress();
void RestoreSectionProtections(const REMOTE_PE_HEADER& PeHeader);
// Overwatch's PE Header and .text section are combined into onememory region with 
// PAGE_EXECUTE_READ protection. This function copies Overwatch's mapped region into a
// remote buffer then writes the secret PE Header at the buffer's base. This buffer is
// the dump target.
SIZE_T BuildNewOverwatchRegion(const REMOTE_PE_HEADER& OverwatchPEHeader);
// This is a hack to force Scylla to recognize the new Overwatch region in the "Pick Dll"
// drop down list. Create / write / insert a LDR_DATA_TABLE_ENTRY for this region into 
// PEB.Ldr.InMemoryOrderModuleList.
bool NoticeMeScylla(const REMOTE_PE_HEADER& NewRegionPEHeader);
bool CombineTextPages(const std::vector<MEMORY_BASIC_INFORMATION>& TextPages,
                      std::vector<MEMORY_BASIC_INFORMATION>& SuspectPages);
bool RemoveGarbageCode(SIZE_T BaseAddress, SIZE_T RegionSize);
// The .text section is segmented by memory regions with PAGE_NOACCESS protection:
// 000000013F050000  0000000000001000  overwatch.exe                        MAP    -R---
// 000000013F051000  00000000000C3000   ".text"         Executable code     MAP    ER---
// 000000013F114000  0000000000001000   ".text"         Executable code     MAP    -----
// 000000013F115000  0000000000002000   ".text"         Executable code     MAP    ER---
// 000000013F117000  0000000000003000   ".text"         Executable code     MAP    -----
// ...
// This function iterates over the .text section to set all pages with
// PAGE_NOACCESS protection to PAGE_EXECUTE_READ protection. This causes
// x64dbg to view the entire section as one section without segmentation.
// The noaccess pages are filled with 0xCC bytes (DISABLED).
bool FixTextSection(const REMOTE_PE_HEADER& PeHeader);
} // namespace archive
#endif

} // namespace fixdump
