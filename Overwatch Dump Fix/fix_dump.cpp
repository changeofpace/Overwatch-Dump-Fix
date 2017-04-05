#include "fix_dump.h"

#include <vector>

#include "memory.h"
#include "nt.h"
#include "ow_imports.h"

///////////////////////////////////////////////////////////////////////////////
// current

// TODO rework how verbose opt is consumed.
bool fixdump::current::FixOverwatch(bool VerboseOutput)
{
    const SIZE_T imagebase = util::GetOverwatchImageBase();
    if (!imagebase)
    {
        pluginLog("Error: failed to locate overwatch's imagebase.\n");
        return false;
    }
    
    pluginLog("Found Overwatch.exe's imagebase at %p.\n", imagebase);

    const SIZE_T secretHeaderBase = util::GetSecretPEHeaderBaseAddress();
    if (!secretHeaderBase)
    {
        pluginLog("Error: failed to locate secret PE Header.\n");
        return false;
    }
    
    pluginLog("Found secret PE header at %p.\n", secretHeaderBase);

    REMOTE_PE_HEADER secretPeHeader;
    if (!FillRemotePeHeader(debuggee::hProcess, secretHeaderBase, secretPeHeader))
    {
        pluginLog("Error: secret PE header at %p was invalid.\n", secretHeaderBase);
        return false;
    }

    std::vector<MEMORY_BASIC_INFORMATION> viewsPageInfo;
    if (!memory::util::GetPageInfo(imagebase, debuggee::imageSize, viewsPageInfo))
    {
        pluginLog("Error: GetPageInfo failed (secret pe header has an invalid image size?).\n");
        return false;
    }

    // TODO: add prot to string from pe header utils
    if (VerboseOutput)
    {
        pluginLog("Found %d views:\n", viewsPageInfo.size());
        for (auto pageInfo : viewsPageInfo)
            pluginLog("    %p  %-16llX  %X\n",
                      pageInfo.BaseAddress,
                      pageInfo.RegionSize,
                      pageInfo.Protect);
    }

    // """"Future proofing"""".
    // Check that there's at least two views.
    if (viewsPageInfo.size() < 2)
    {
        pluginLog("Error: found unexpected number of views (%d). A patch has probably introduced new anti-dumping protection so this plugin needs to be updated.\n",
                  viewsPageInfo.size());
        return false;
    }
    // 2.25.2017: There are 9 views (.rdata is split into two views).
    // The plugin should still work as long as .text and .rdata are the first
    // two views.
    // 3.6.2017: there are 11 views.
    else if (viewsPageInfo.size() != 11)
    {
        pluginLog("Warning: found unexpected number of views (%d).\n",
                  viewsPageInfo.size());
    }

    // Remap the views representing .text and .rdata with PAGE_EXECUTE_READWRITE protection.
    // note: only the first .rdata is remapped.
    MEMORY_BASIC_INFORMATION textView = viewsPageInfo[0];
    MEMORY_BASIC_INFORMATION rdataView = viewsPageInfo[1];

    auto remapView = [&VerboseOutput](const MEMORY_BASIC_INFORMATION& ViewPageInfo)
    {
        if (VerboseOutput)
            pluginLog("Remapping view at %p (%llX) with %X protection.\n",
                      ViewPageInfo.BaseAddress,
                      ViewPageInfo.RegionSize,
                      ViewPageInfo.Protect);
        if (!memory::RemapViewOfSection(SIZE_T(ViewPageInfo.BaseAddress), ViewPageInfo.RegionSize))
            pluginLog("Error: failed to remap view at %p (%llX) with %X protection.\n",
                      ViewPageInfo.BaseAddress,
                      ViewPageInfo.RegionSize,
                      ViewPageInfo.Protect);
    };

    remapView(textView);
    remapView(rdataView);

    // Fix the local PE Header for Overwatch.exe then apply it to the debuggee.
    if (!RestorePeHeader(secretPeHeader))
    {
        pluginLog("Error: failed to write local PE Header to %p.\n", secretPeHeader.optionalHeader->ImageBase);
        return false;
    }

    // Unpack imports.
    REMOTE_PE_HEADER restoredPeHeader;
    if (!FillRemotePeHeader(debuggee::hProcess, imagebase, restoredPeHeader))
    {
        pluginLog("Error: restored PE header at %p was invalid.\n", imagebase);
        return false;
    }

    if (!owimports::RebuildImports(restoredPeHeader))
    {
        pluginLog("Error: failed to rebuild imports.\n");
        return false;
    }

    // Restore .text .rdata's view page protection to the expected value.
    auto restoreProtection = [&VerboseOutput](PVOID BaseAddress, SIZE_T RegionSize, DWORD NewProtection)
    {
        if (VerboseOutput)
            pluginLog("Restoring protection at %p (%llX) to %X\n",
                      BaseAddress,
                      RegionSize,
                      NewProtection);

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(debuggee::hProcess,
                              BaseAddress,
                              RegionSize,
                              NewProtection,
                              &oldProtection))
            pluginLog("Warning: failed to restore view protection at %p (%llX).\n",
                      BaseAddress,
                      RegionSize);
    };

    restoreProtection(textView.BaseAddress, textView.RegionSize, PAGE_EXECUTE_READ);
    restoreProtection(rdataView.BaseAddress, rdataView.RegionSize, PAGE_READONLY);
    // 0x1000 bytes of .text spill over into .rdata. The IAT is still at .rdata + 0x1000.
    // IDA will automatically combine the two .text sections into one.
    restoreProtection(rdataView.BaseAddress, PAGE_SIZE, PAGE_EXECUTE_READ);
    // Restore the PE header.
    restoreProtection(textView.BaseAddress, PE_HEADER_SIZE, PAGE_READONLY);

    return true;
}

bool fixdump::current::RestorePeHeader(REMOTE_PE_HEADER& PeHeader)
{
    // Individual field fixups.
    PeHeader.optionalHeader->ImageBase = util::GetOverwatchImageBase();

    // Patch Overwatch.exe's PE Header.
    return memory::util::RemoteWrite(PeHeader.optionalHeader->ImageBase, PVOID(PeHeader.rawData), PE_HEADER_SIZE);
}

///////////////////////////////////////////////////////////////////////////////
// util

SIZE_T fixdump::util::GetOverwatchImageBase()
{
    return debuggee::imageBase;
}

SIZE_T fixdump::util::GetSecretPEHeaderBaseAddress()
{
    const SIZE_T imagebase = GetOverwatchImageBase();
    for (SIZE_T ea = 0x10000; ea < imagebase; /**/)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(debuggee::hProcess, PVOID(ea), &mbi, sizeof(mbi)))
        {
            pluginLog("Error: VirtualQueryEx failed for %p: .%d.\n", ea, GetLastError());
            return 0;
        }

        //pluginLog("base: %p  alloc: %p  size: %p  state: %8X  type: %8X  prot: %8X\n",
        //          mbi.BaseAddress,
        //          mbi.AllocationBase,
        //          mbi.RegionSize,
        //          mbi.State,
        //          mbi.Type,
        //          mbi.Protect);

        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD))
        {
            BYTE data[PE_HEADER_SIZE] = {};
            if (!memory::util::RemoteRead(SIZE_T(mbi.BaseAddress), data, PE_HEADER_SIZE))
            {
                pluginLog("RemoteRead failed for %p while scanning for secret pe header.\n", ea);
                return 0;
            }

            REMOTE_PE_HEADER pe;
            if (FillRemotePeHeader(debuggee::hProcess, SIZE_T(mbi.BaseAddress), pe))
            {
                pluginLog("Found vald PE header at %p.\n", mbi.BaseAddress);
                if (pe.optionalHeader->SizeOfImage == debuggee::imageSize)
                    return SIZE_T(mbi.BaseAddress);
            }
        }

        ea = SIZE_T(mbi.BaseAddress) + mbi.RegionSize;
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// archive

namespace fixdump {
namespace archive {

void RestoreSectionProtections(const REMOTE_PE_HEADER& PeHeader)
{
    auto restoreProtection = [](PVOID BaseAddress, SIZE_T RegionSize, DWORD NewProtection)
    {
        //pluginLog("restoring protection at %p, %8llX to %X\n",
        //          BaseAddress,
        //          RegionSize,
        //          NewProtection);

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(debuggee::hProcess,
            BaseAddress,
            RegionSize,
            NewProtection,
            &oldProtection))
            pluginLog("Warning: failed to restore section protection at %p, %8llX.\n",
            BaseAddress,
            RegionSize);
    };

    std::vector<MEMORY_BASIC_INFORMATION> memRegions;
    if (!memory::util::GetPageInfo(PeHeader.optionalHeader->ImageBase,
        PeHeader.optionalHeader->SizeOfImage,
        memRegions))
    {
        pluginLog("Error: GetPageInfo failed while restoring page protection.\n");
        return;
    }

    if (memRegions.size() != 8)
    {
        pluginLog("Error: Unexpected view layout, section protection will not be restored.\n");
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

SIZE_T BuildNewOverwatchRegion(const REMOTE_PE_HEADER& OverwatchPEHeader)
{
    LPVOID newOverwatchRegion = VirtualAllocEx(debuggee::hProcess,
                                               NULL,
                                               OverwatchPEHeader.optionalHeader->SizeOfImage,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_EXECUTE_READWRITE);
    if (!newOverwatchRegion)
    {
        pluginLog("BuildNewOverwatchRegion: VirtualAllocEx failed %d.\n", GetLastError());
        return 0;
    }

    LPVOID transferBuffer = VirtualAlloc(NULL,
                                         OverwatchPEHeader.optionalHeader->SizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!transferBuffer)
    {
        pluginLog("BuildNewOverwatchRegion: VirtualAlloc failed %d.\n", GetLastError());
        return 0;
    }

    if (const SIZE_T secretPEHeaderAddress = fixdump::util::GetSecretPEHeaderBaseAddress())
    {
        if (memory::util::RemoteRead(OverwatchPEHeader.remoteBaseAddress,
                                transferBuffer,
                                OverwatchPEHeader.optionalHeader->SizeOfImage) &&
            memory::util::RemoteRead(secretPEHeaderAddress, transferBuffer, PE_HEADER_SIZE) &&
            memory::util::RemoteWrite(SIZE_T(newOverwatchRegion),
                                 transferBuffer,
                                 OverwatchPEHeader.optionalHeader->SizeOfImage))
        {
            VirtualFree(transferBuffer, 0, MEM_RELEASE);
            return SIZE_T(newOverwatchRegion);
        }
        else
            pluginLog("BuildNewOverwatchRegion: Failed to write transfer buffer to Overwatch.exe.\n");
    }
    else
        pluginLog("BuildNewOverwatchRegion: GetSecretPEHeaderBaseAddress failed.\n");

    VirtualFreeEx(debuggee::hProcess,newOverwatchRegion, 0, MEM_RELEASE);
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
        pluginLog("NoticeMeScylla: VirtualAllocEx failed for remoteEntryAddress, %d.\n",
                  GetLastError());
        return false;
    }

    const SIZE_T peb = DbgGetPebAddress(DbgGetProcessId());
    if (!peb)
    {
        pluginLog("NoticeMeScylla: DbgGetPebAddress failed.\n");
        return false;
    }

    SIZE_T ldr = 0;
    SIZE_T listHeadAddress = 0;
    SIZE_T listHeadFlink = 0;
    SIZE_T overwatchEntryAddress = 0;
    LIST_ENTRY newEntry = {};
    LIST_ENTRY listHead = {};
    LDR_DATA_TABLE_ENTRY localModuleEntry = {};

    // get PEB_LDR_DATA.InMemoryOrderModuleList.
    memory::util::RemoteRead(peb + FIELD_OFFSET(PEB, Ldr), &ldr, sizeof(SIZE_T));
    listHeadAddress = ldr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList);
    memory::util::RemoteRead(listHeadAddress, &listHead, sizeof(LIST_ENTRY));

    // read Overwatch.exe's LDR_DATA_TABLE_ENTRY.
    memory::util::RemoteRead(listHeadAddress, &listHeadFlink, sizeof(SIZE_T));
    overwatchEntryAddress = listHeadFlink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    memory::util::RemoteRead(overwatchEntryAddress, &localModuleEntry, sizeof(localModuleEntry));

    // insert the new entry at the tail of InMemoryOrderModuleList.

    // Entry->Flink = ListHead;
    // Entry->Blink = PrevEntry;
    newEntry.Flink = PLIST_ENTRY(listHeadAddress);
    newEntry.Blink = listHead.Blink;

    // PrevEntry->Flink = Entry;
    const SIZE_T newEntryMemoryOrderLinks = SIZE_T(remoteEntryAddress) +
                                           FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    memory::util::RemoteWrite(SIZE_T(listHead.Blink), PVOID(&newEntryMemoryOrderLinks), sizeof(SIZE_T));

    // ListHead->Blink = Entry;
    memory::util::RemoteWrite(listHeadAddress + sizeof(SIZE_T), &remoteEntryAddress, sizeof(SIZE_T));

    localModuleEntry.DllBase = PVOID(NewRegionPEHeader.remoteBaseAddress);
    localModuleEntry.EntryPoint = PVOID(NewRegionPEHeader.remoteBaseAddress +
                                        NewRegionPEHeader.optionalHeader->AddressOfEntryPoint);
    localModuleEntry.SizeOfImage = NewRegionPEHeader.optionalHeader->SizeOfImage;
    localModuleEntry.InMemoryOrderLinks = newEntry;

    if (!memory::util::RemoteWrite(SIZE_T(remoteEntryAddress), &localModuleEntry, sizeof(localModuleEntry)))
    {
        pluginLog("NoticeMeScylla: RemoteWrite failed for localModuleEntry, %d.\n", GetLastError());
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

bool RemoveGarbageCode(SIZE_T BaseAddress, SIZE_T RegionSize)
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
    const SIZE_T textBase = PEHeader.remoteBaseAddress + textSection->VirtualAddress;

    std::vector<MEMORY_BASIC_INFORMATION> textPages;
    if (!memory::util::GetPageInfo(textBase, textSection->Misc.VirtualSize, textPages))
    {
        pluginLog("FixTextSection:  failed to get text section pages using range %p - %p.\n",
                  textBase,
                  textBase + textSection->Misc.VirtualSize);
        return false;
    }

    // save the mbi for pages with PAGE_NOACCESS protection before combining
    std::vector<MEMORY_BASIC_INFORMATION> suspectPages;
    if (!CombineTextPages(textPages, suspectPages))
    {
        pluginLog("FixTextSection:  failed to combine text section pages.");
        return false;
    }

    /* special case patching */

    // the first 'real' function in .text seems to start at an arbitrary offset.
    // this function calls 'InitializeCriticalSection'.
    // this value changed in the 12.13.2016 patch: 0xB2161.
    // 2.14.2017 this value is dynamic.
    const SIZE_T firstFunctionOffset = 0xBFF80;
    if (!RemoveGarbageCode(textBase, firstFunctionOffset))
    {
        pluginLog("FixTextSection:  failed to remove garbage code at %p (+%X)\n.",
                  textBase,
                  firstFunctionOffset);
        return false;
    }

    //plog("first function:  %p\n", textSectionBase + firstFunctionOffset);

    // fill the PAGE_NOACCESS pages with 0xCC.
    //for (auto page : suspectPages)
    //{
    //    if (!RemoveGarbageCode(SIZE_T(page.BaseAddress), page.RegionSize))
    //    {
    //        pluginLog("FixTextSection:  failed to remove garbage code for suspicious page at %p (%X)\n.",
    //                  textSectionBase,
    //                  firstFunctionOffset);
    //        return false;
    //    }
    //}

    return true;
}

} // namespace archive
} // namespace fixdump