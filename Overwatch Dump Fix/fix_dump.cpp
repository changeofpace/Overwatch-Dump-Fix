#include "fix_dump.h"

#include <vector>

#include "debug.h"
#include "memory.h"
#include "nt.h"
#include "ow_imports.h"

///////////////////////////////////////////////////////////////////////////////
// current

void fixdump::current::FixOverwatch()
{
    const duint imagebase = util::GetOverwatchImageBase();
    if (!imagebase)
    {
        PluginLog("Error: failed to locate overwatch's imagebase.\n");
        return;
    }
    const duint secretHeaderBase = util::GetSecretPEHeaderBaseAddress();
    if (!secretHeaderBase)
    {
        PluginLog("Error: failed to locate secret PE Header.\n");
        return;
    }

    REMOTE_PE_HEADER secretPeHeader;
    if (!FillRemotePeHeader(debuggee::hProcess, secretHeaderBase, secretPeHeader))
        return;

    std::vector<MEMORY_BASIC_INFORMATION> pageInfo;
    if (!memory::util::GetPageInfo(imagebase, secretPeHeader.optionalHeader->SizeOfImage, pageInfo))
    {
        PluginLog("Error: GetPageInfo failed (secret pe header has an invalid image size?).\n");
        return;
    }

    //for (auto page : pageInfo)
    //    plugindbg::DumpMemoryBasicInformationShort(page);

    // Remap every memory mapped view with PAGE_EXECUTE_READWRITE protection.
    for (const auto& page: pageInfo)
    {
        //PluginLog("remapping  %p  %16llX\n", page.BaseAddress, page.RegionSize);
        if (!memory::RemapViewOfSection(SIZE_T(page.BaseAddress), page.RegionSize))
            PluginLog("Error: failed to remap view at %p, %llX.\n", page.BaseAddress, page.RegionSize);
    }

    // .rdata is split into two views, combine them.
    if (!memory::CombineAdjacentViews(
        std::vector<MEMORY_BASIC_INFORMATION>(pageInfo.begin() + 1, pageInfo.begin() + 3)))
            return;

    if (!RestorePeHeader(secretPeHeader))
    {
        PluginLog("Error: failed to write local PE Header to %p.\n", secretPeHeader.optionalHeader->ImageBase);
        return;
    }

    REMOTE_PE_HEADER restoredPeHeader;
    if (!FillRemotePeHeader(debuggee::hProcess, imagebase, restoredPeHeader))
        return;

    if (!owimports::RebuildImports(restoredPeHeader))
        return;

    RestoreSectionProtections(secretPeHeader);

    PluginLog("completed successfully. Use Scylla to dump Overwatch.exe.\n");
}

bool fixdump::current::RestorePeHeader(REMOTE_PE_HEADER& PeHeader)
{
    // Individual field fixups.
    PeHeader.optionalHeader->ImageBase = util::GetOverwatchImageBase();

    // Patch Overwatch.exe's PE Header.
    return memory::util::RemoteWrite(PeHeader.optionalHeader->ImageBase, PVOID(PeHeader.rawData), PE_HEADER_SIZE);
}

void fixdump::current::RestoreSectionProtections(const REMOTE_PE_HEADER& PeHeader)
{
    auto restoreProtection = [](PVOID BaseAddress, SIZE_T RegionSize, DWORD NewProtection)
    {
        //PluginLog("restoring protection at %p, %8llX to %X\n",
        //          BaseAddress,
        //          RegionSize,
        //          NewProtection);

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(debuggee::hProcess,
                              BaseAddress,
                              RegionSize,
                              NewProtection,
                              &oldProtection))
            PluginLog("Warning: failed to restore section protection at %p, %8llX.\n",
                       BaseAddress,
                       RegionSize);
    };

    std::vector<MEMORY_BASIC_INFORMATION> memRegions;
    if (!memory::util::GetPageInfo(PeHeader.optionalHeader->ImageBase,
                                   PeHeader.optionalHeader->SizeOfImage,
                                   memRegions))
    {
        PluginLog("Error: GetPageInfo failed while restoring page protection.\n");
        return;
    }

    if (memRegions.size() != 8)
    {
        PluginLog("Error: Unexpected view layout, section protection will not be restored.\n");
        return;
    }

    restoreProtection(memRegions[0].BaseAddress, memRegions[0].RegionSize, PAGE_EXECUTE_READ);  // .text
    restoreProtection(memRegions[1].BaseAddress, memRegions[1].RegionSize, PAGE_READONLY);      // .rdata
    restoreProtection(memRegions[2].BaseAddress, memRegions[2].RegionSize, PAGE_READWRITE);     // .data
    restoreProtection(memRegions[3].BaseAddress, memRegions[3].RegionSize, PAGE_READWRITE);     // .data
    restoreProtection(memRegions[4].BaseAddress, memRegions[4].RegionSize, PAGE_READONLY);      // .pdata
    restoreProtection(memRegions[5].BaseAddress, memRegions[5].RegionSize, PAGE_READWRITE);     // .tls
    restoreProtection(memRegions[6].BaseAddress, memRegions[6].RegionSize, PAGE_READONLY);      // . _RDATA ?
    restoreProtection(memRegions[7].BaseAddress, memRegions[7].RegionSize, PAGE_READONLY);      // .rsrc / .reloc ?

    // Pe header
    restoreProtection(PVOID(PeHeader.optionalHeader->ImageBase), PE_HEADER_SIZE, PAGE_READONLY);
}

///////////////////////////////////////////////////////////////////////////////
// util

duint fixdump::util::GetOverwatchImageBase()
{
    return DbgValFromString("overwatch.exe:0");
}

// TODO: rewrite with ntqvm using IsValidPEHeader
duint fixdump::util::GetSecretPEHeaderBaseAddress()
{
    MEMMAP memmap;
    if (DbgMemMap(&memmap))
    {
        for (int i = 0; i < memmap.count; i++)
        {
            MEMPAGE* page = &memmap.page[i];
            if (page->mbi.RegionSize == PE_HEADER_SIZE)
            {
                WORD dosMagic = 0;
                if (memory::util::RemoteRead(duint(page->mbi.AllocationBase), PVOID(&dosMagic), sizeof(dosMagic)))
                {
                    if (dosMagic == IMAGE_DOS_SIGNATURE)
                        return duint(page->mbi.AllocationBase);
                }
            }
        }
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// archive

namespace fixdump {
namespace archive {

duint BuildNewOverwatchRegion(const REMOTE_PE_HEADER& OverwatchPEHeader)
{
    LPVOID newOverwatchRegion = VirtualAllocEx(debuggee::hProcess,
                                               NULL,
                                               OverwatchPEHeader.optionalHeader->SizeOfImage,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_EXECUTE_READWRITE);
    if (!newOverwatchRegion)
    {
        PluginLog("BuildNewOverwatchRegion: VirtualAllocEx failed %d.\n", GetLastError());
        return 0;
    }

    LPVOID transferBuffer = VirtualAlloc(NULL,
                                         OverwatchPEHeader.optionalHeader->SizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!transferBuffer)
    {
        PluginLog("BuildNewOverwatchRegion: VirtualAlloc failed %d.\n", GetLastError());
        return 0;
    }

    if (const duint secretPEHeaderAddress = fixdump::util::GetSecretPEHeaderBaseAddress())
    {
        if (memory::util::RemoteRead(OverwatchPEHeader.remoteBaseAddress,
                                transferBuffer,
                                OverwatchPEHeader.optionalHeader->SizeOfImage) &&
            memory::util::RemoteRead(secretPEHeaderAddress, transferBuffer, PE_HEADER_SIZE) &&
            memory::util::RemoteWrite(duint(newOverwatchRegion),
                                 transferBuffer,
                                 OverwatchPEHeader.optionalHeader->SizeOfImage))
        {
            VirtualFree(transferBuffer, 0, MEM_RELEASE);
            return duint(newOverwatchRegion);
        }
        else
            PluginLog("BuildNewOverwatchRegion: Failed to write transfer buffer to Overwatch.exe.\n");
    }
    else
        PluginLog("BuildNewOverwatchRegion: GetSecretPEHeaderBaseAddress failed.\n");

    VirtualFreeEx(debuggee::hProcess,
                  newOverwatchRegion,
                  OverwatchPEHeader.optionalHeader->SizeOfImage,
                  MEM_RELEASE);
    VirtualFree(transferBuffer, 0, MEM_RELEASE);
    return 0;
}

bool NoticeMeScylla(const REMOTE_PE_HEADER& NewRegionPEHeader)
{
    LPVOID remoteEntryAddress = VirtualAllocEx(debuggee::hProcess,
                                               NULL,
                                               sizeof(LDR_DATA_TABLE_ENTRY),
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_EXECUTE_READWRITE);
    if (!remoteEntryAddress)
    {
        PluginLog("NoticeMeScylla: VirtualAllocEx failed for remoteEntryAddress, %d.\n",
                  GetLastError());
        return false;
    }

    const duint peb = DbgGetPebAddress(DbgGetProcessId());
    if (!peb)
    {
        PluginLog("NoticeMeScylla: DbgGetPebAddress failed.\n");
        return false;
    }

    duint ldr = 0;
    duint listHeadAddress = 0;
    duint listHeadFlink = 0;
    duint overwatchEntryAddress = 0;
    LIST_ENTRY newEntry = {};
    LIST_ENTRY listHead = {};
    LDR_DATA_TABLE_ENTRY localModuleEntry = {};

    // get PEB_LDR_DATA.InMemoryOrderModuleList.
    memory::util::RemoteRead(peb + FIELD_OFFSET(PEB, Ldr), &ldr, sizeof(duint));
    listHeadAddress = ldr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList);
    memory::util::RemoteRead(listHeadAddress, &listHead, sizeof(LIST_ENTRY));

    // read Overwatch.exe's LDR_DATA_TABLE_ENTRY.
    memory::util::RemoteRead(listHeadAddress, &listHeadFlink, sizeof(duint));
    overwatchEntryAddress = listHeadFlink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    memory::util::RemoteRead(overwatchEntryAddress, &localModuleEntry, sizeof(localModuleEntry));

    // insert the new entry at the tail of InMemoryOrderModuleList.

    // Entry->Flink = ListHead;
    // Entry->Blink = PrevEntry;
    newEntry.Flink = PLIST_ENTRY(listHeadAddress);
    newEntry.Blink = listHead.Blink;

    // PrevEntry->Flink = Entry;
    const duint newEntryMemoryOrderLinks = duint(remoteEntryAddress) +
                                           FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    memory::util::RemoteWrite(duint(listHead.Blink), PVOID(&newEntryMemoryOrderLinks), sizeof(duint));

    // ListHead->Blink = Entry;
    memory::util::RemoteWrite(listHeadAddress + sizeof(duint), &remoteEntryAddress, sizeof(duint));

    localModuleEntry.DllBase = PVOID(NewRegionPEHeader.remoteBaseAddress);
    localModuleEntry.EntryPoint = PVOID(NewRegionPEHeader.remoteBaseAddress +
                                        NewRegionPEHeader.optionalHeader->AddressOfEntryPoint);
    localModuleEntry.SizeOfImage = NewRegionPEHeader.optionalHeader->SizeOfImage;
    localModuleEntry.InMemoryOrderLinks = newEntry;

    if (!memory::util::RemoteWrite(duint(remoteEntryAddress), &localModuleEntry, sizeof(localModuleEntry)))
    {
        PluginLog("NoticeMeScylla: RemoteWrite failed for localModuleEntry, %d.\n", GetLastError());
        return false;
    }

    return true;
}

bool CombineTextPages(const std::vector<MEMORY_BASIC_INFORMATION>& TextPages,
                      std::vector<MEMORY_BASIC_INFORMATION>& SuspectPages)
{
    for (auto page : TextPages)
    {
        if (page.Protect == PAGE_NOACCESS)
        {
            DWORD useless;
            SuspectPages.push_back(page);
            if (!VirtualProtectEx(debuggee::hProcess, page.BaseAddress, page.RegionSize, PAGE_EXECUTE_READ, &useless))
                return false;
        }
    }
    return true;
}

bool RemoveGarbageCode(duint BaseAddress, SIZE_T RegionSize)
{
    bool status = false;
    DWORD oldprot;
    if (VirtualProtectEx(debuggee::hProcess, PVOID(BaseAddress), RegionSize, PAGE_EXECUTE_READWRITE, &oldprot))
    {
        PBYTE cc = new BYTE[RegionSize];
        FillMemory(cc, RegionSize, 0xCC);
        if (DbgMemWrite(BaseAddress, cc, RegionSize))
        {
            DWORD useless;
            if (VirtualProtectEx(debuggee::hProcess, PVOID(BaseAddress), RegionSize, oldprot, &useless))
                status = true;
        }
        delete[] cc;
    }
    return status;
}

bool FixTextSection(const REMOTE_PE_HEADER& PEHeader)
{
    const PIMAGE_SECTION_HEADER textSection = GetPeSectionByName(PEHeader, ".text");
    const duint textBase = PEHeader.remoteBaseAddress + textSection->VirtualAddress;

    std::vector<MEMORY_BASIC_INFORMATION> textPages;
    if (!memory::util::GetPageInfo(textBase, textSection->Misc.VirtualSize, textPages))
    {
        PluginLog("FixTextSection:  failed to get text section pages using range %p - %p.\n",
                  textBase,
                  textBase + textSection->Misc.VirtualSize);
        return false;
    }

    // save the mbi for pages with PAGE_NOACCESS protection before combining
    std::vector<MEMORY_BASIC_INFORMATION> suspectPages;
    if (!CombineTextPages(textPages, suspectPages))
    {
        PluginLog("FixTextSection:  failed to combine text section pages.");
        return false;
    }

    /* special case patching */

    // the first 'real' function in .text seems to start at an arbitrary offset.
    // this function calls 'InitializeCriticalSection'.
    // this value changed in the 12.13.2016 patch: 0xB2161.
    // 2.14.2017 this value is dynamic.
    const duint firstFunctionOffset = 0xBFF80;
    if (!RemoveGarbageCode(textBase, firstFunctionOffset))
    {
        PluginLog("FixTextSection:  failed to remove garbage code at %p (+%X)\n.",
                  textBase,
                  firstFunctionOffset);
        return false;
    }

    //plog("first function:  %p\n", textSectionBase + firstFunctionOffset);

    // fill the PAGE_NOACCESS pages with 0xCC.
    //for (auto page : suspectPages)
    //{
    //    if (!RemoveGarbageCode(duint(page.BaseAddress), page.RegionSize))
    //    {
    //        PluginLog("FixTextSection:  failed to remove garbage code for suspicious page at %p (%X)\n.",
    //                  textSectionBase,
    //                  firstFunctionOffset);
    //        return false;
    //    }
    //}

    return true;
}

} // namespace archive
} // namespace fixdump