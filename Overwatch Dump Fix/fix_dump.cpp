#include "fix_dump.h"

#include <Psapi.h>
#include <Shlwapi.h>

#include <vector>

#include "memory.h"
#include "nt.h"
#include "ow_imports.h"

bool fixdump::current::FixOverwatch()
{
    BUFFERED_PE_HEADER peHeader;
    if (!GetOverwatchPeHeader(peHeader)) {
        pluginLog("Error: failed to get Overwatch's PE header.\n");
        return false;
    }

    std::vector<MEMORY_BASIC_INFORMATION> memoryViews;
    if (!memory::util::GetPageInfo(debuggee.imageBase, debuggee.imageSize,
                                   memoryViews)) {
        pluginLog("Error: failed to get memory views.\n");
        return false;
    }

    pluginLog("Found %d views:\n", memoryViews.size());
    for (auto view_info : memoryViews) {
        pluginLog("    %p  %16llX  %X\n", view_info.BaseAddress,
                  view_info.RegionSize, view_info.Protect);
    }

    // Make overwatch's pe header, .text, and .rdata regions writable.
    if (!memory::RemapViewOfSection(size_t(memoryViews[0].BaseAddress),
                                    memoryViews[0].RegionSize)) {
        pluginLog("Error: failed to remap view at %p (%llX).\n",
                  memoryViews[0].BaseAddress, memoryViews[0].RegionSize);
        return false;
    }

    FixPeHeader(peHeader);

    if (!RestorePeHeader(peHeader)) {
        pluginLog("Error: failed to write PE Header to %p.\n", debuggee.imageBase);
        return false;
    }

    REMOTE_PE_HEADER restoredPeHeader;
    if (!FillRemotePeHeader(debuggee.hProcess, debuggee.imageBase, restoredPeHeader)) {
        pluginLog("Error: restored PE header at %p was invalid.\n", debuggee.imageBase);
        return false;
    }

    if (!owimports::RebuildImports(restoredPeHeader)) {
        pluginLog("Error: failed to rebuild imports.\n");
        return false;
    }

    if (!SplitSections(restoredPeHeader)) {
        pluginLog("Error: failed to split pe sections.\n");
        return false;
    }

    return true;
}

//bool fixdump::current::GetOverwatchPeHeader(BUFFERED_PE_HEADER& PeHeader) {
//    std::ifstream in(debuggee.image_name, std::ios::binary);
//    if (!in.is_open())
//        return false;
//    unsigned char buffer[PE_HEADER_SIZE] = {};
//    in.read((char*)buffer, PE_HEADER_SIZE);
//    return in && FillBufferedPeHeader(buffer, PE_HEADER_SIZE, PeHeader);
//}

bool fixdump::current::GetOverwatchPeHeader(BUFFERED_PE_HEADER& PeHeader)
{
    wchar_t overwatchPath[MAX_MODULE_SIZE] = {};
    if (!GetModuleFileNameExW(debuggee.hProcess,
                              nullptr,
                              overwatchPath,
                              MAX_MODULE_SIZE)) {
        pluginLog("Error: failed to get Overwatch's path.\n");
        return false;
    }

    HANDLE hOverwatchFile = CreateFileW(overwatchPath,
                                        GENERIC_READ,
                                        FILE_SHARE_READ,
                                        nullptr,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        nullptr);
    if (hOverwatchFile == INVALID_HANDLE_VALUE) {
        pluginLog("Error: failed to open Overwatch.exe while getting pe header.\n");
        return false;
    }

    DWORD numBytesRead = 0;
    if (!ReadFile(hOverwatchFile,
                  LPVOID(PeHeader.rawData),
                  PE_HEADER_SIZE,
                  &numBytesRead,
                  nullptr)) {
        pluginLog("Error: failed to read Overwatch.exe.\n");
        CloseHandle(hOverwatchFile);
        return false;
    }

    // HACK 4.29.2017: pe header code needs a rewrite and so does this.
    if (!FillPeHeader(SIZE_T(PeHeader.rawData), PeHeader)) {
        pluginLog("Error: failed to create pe header from read buffer.\n");
        CloseHandle(hOverwatchFile);
        return false;
    }

    CloseHandle(hOverwatchFile);
    return true;
}

void fixdump::current::FixPeHeader(BUFFERED_PE_HEADER& PeHeader)
{
    PeHeader.optionalHeader->ImageBase = debuggee.imageBase;
}

bool fixdump::current::RestorePeHeader(BUFFERED_PE_HEADER& PeHeader)
{
    return memory::util::RemoteWrite(debuggee.imageBase,
                                     PVOID(PeHeader.rawData),
                                     PE_HEADER_SIZE);
}

bool fixdump::current::SplitSections(const REMOTE_PE_HEADER& PeHeader)
{
    auto SetPageProtection = [](size_t BaseAddress,
                                size_t RegionSize,
                                DWORD NewProtection)
    {
        pluginLog("Restoring protection at %p (%llX) to %X.\n", BaseAddress,
                  RegionSize, NewProtection);

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(debuggee.hProcess, PVOID(BaseAddress),
                              RegionSize, NewProtection, &oldProtection)) {
            pluginLog("Warning: failed to restore view protection at %p (%llX), error code %d.\n",
                      BaseAddress, RegionSize, GetLastError());
        }
    };

    PIMAGE_SECTION_HEADER textSection = GetPeSectionByName(PeHeader, ".text");
    PIMAGE_SECTION_HEADER rdataSection = GetPeSectionByName(PeHeader, ".rdata");
    if (!textSection || !rdataSection) {
        pluginLog("Error: failed to find .text or .rdata section header pointers.\n");
        return false;
    }

    SetPageProtection(debuggee.imageBase,
                      PE_HEADER_SIZE,
                      PAGE_READONLY);
    SetPageProtection(debuggee.imageBase + textSection->VirtualAddress,
                      textSection->Misc.VirtualSize,
                      PAGE_EXECUTE_READ);
    // BUG 4.18.2017: this fails with error code 298 ERROR_TOO_MANY_POSTS. I fixed this
    // issue with RPM / WPM by using custom wrappers instead of the plugin sdk
    // wrappers. Adding a Sleep(X000) before this call changes the error code to
    // 487 ERROR_INVALID_ADDRESS. I have no idea why this happens or how to fix it.
    // Even if it fails .rdata should still be separated from .text as long as
    // the call above succeeds.
    SetPageProtection(debuggee.imageBase + rdataSection->VirtualAddress,
                      rdataSection->Misc.VirtualSize,
                      PAGE_READONLY);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// archive

namespace fixdump {
namespace archive {

SIZE_T GetSecretPEHeaderBaseAddress() {
    const SIZE_T imagebase = debuggee.imageBase;
    for (SIZE_T ea = 0x10000; ea < imagebase; /**/)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(debuggee.hProcess, PVOID(ea), &mbi, sizeof(mbi)))
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
            if (FillRemotePeHeader(debuggee.hProcess, SIZE_T(mbi.BaseAddress), pe))
            {
                pluginLog("Found vald PE header at %p.\n", mbi.BaseAddress);
                if (pe.optionalHeader->SizeOfImage == debuggee.imageSize)
                    return SIZE_T(mbi.BaseAddress);
            }
        }

        ea = SIZE_T(mbi.BaseAddress) + mbi.RegionSize;
    }
    return 0;
}

void RestoreSectionProtections(const REMOTE_PE_HEADER& PeHeader)
{
    auto restoreProtection = [](PVOID BaseAddress, SIZE_T RegionSize, DWORD NewProtection)
    {
        //pluginLog("restoring protection at %p, %8llX to %X\n",
        //          BaseAddress,
        //          RegionSize,
        //          NewProtection);

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(debuggee.hProcess,
                              BaseAddress,
                              RegionSize,
                              NewProtection,
                              &oldProtection)) {
            pluginLog("Warning: failed to restore section protection at %p, %8llX.\n",
                      BaseAddress, RegionSize);
        }
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
    LPVOID newOverwatchRegion = VirtualAllocEx(debuggee.hProcess,
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

    if (const SIZE_T secretPEHeaderAddress = GetSecretPEHeaderBaseAddress())
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

    VirtualFreeEx(debuggee.hProcess,newOverwatchRegion, 0, MEM_RELEASE);
    VirtualFree(transferBuffer, 0, MEM_RELEASE);
    return 0;
}

bool NoticeMeScylla(const REMOTE_PE_HEADER& NewRegionPEHeader)
{
    LPVOID remoteEntryAddress = VirtualAllocEx(debuggee.hProcess,
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
            if (!VirtualProtectEx(debuggee.hProcess, page.BaseAddress, page.RegionSize, PAGE_EXECUTE_READ, &useless))
                return false;
        }
    }
    return true;
}

bool RemoveGarbageCode(SIZE_T BaseAddress, SIZE_T RegionSize)
{
    bool status = false;
    DWORD oldprot;
    if (VirtualProtectEx(debuggee.hProcess, PVOID(BaseAddress), RegionSize, PAGE_EXECUTE_READWRITE, &oldprot))
    {
        PBYTE cc = new BYTE[RegionSize];
        FillMemory(cc, RegionSize, 0xCC);
        if (DbgMemWrite(BaseAddress, cc, RegionSize))
        {
            DWORD useless;
            if (VirtualProtectEx(debuggee.hProcess, PVOID(BaseAddress), RegionSize, oldprot, &useless))
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