#include "fix_dump.h"
#include "memory_util.h"
#include "nt.h"
#include "ow_imports.h"

////////////////////////////////////////////////////////////////////////////////
// current

void fix_dump::current::FixOverwatch()
{
    REMOTE_PE_HEADER overwatchPEHeader;
    if (!FillRemotePEHeader(debuggee::hProcess, util::GetOverwatchImageBase(), overwatchPEHeader))
    {
        PluginLog("FillRemotePEHeader failed for Overwatch.exe.\n");
        return;
    }

    duint newOverwatchRegion = BuildNewOverwatchRegion(overwatchPEHeader);
    if (!newOverwatchRegion)
        return;

    REMOTE_PE_HEADER newRegionPEHeader;
    if (!FillRemotePEHeader(debuggee::hProcess, duint(newOverwatchRegion), newRegionPEHeader))
    {
        PluginLog("FillRemotePEHeader failed for the new Overwatch region.\n");
        return;
    }

    if (!RestorePEHeader(overwatchPEHeader, newRegionPEHeader))
    {
        PluginLog("RestorePEHeader failed %d.\n", GetLastError());
        return;
    }

    if (!RebuildImports(newRegionPEHeader))
        return;

    RestoreSectionProtection(newRegionPEHeader);

    if (!NoticeMeScylla(newRegionPEHeader))
        return;

    PluginLog("dump fix complete.\n");

    ScyllaIATInfo scyllaInfo = GetScyllaInfo();

    PluginLog("Scylla IAT Info:\n");
    PluginLog("    OEP =  %p\n", scyllaInfo.oep);
    PluginLog("    VA =   %p\n", scyllaInfo.va);
    PluginLog("    Size = %16llX\n", scyllaInfo.size);

    PluginLog("IDA Pro Info:\n");
    PluginLog("    overwatch base address = %p\n", overwatchPEHeader.remoteBaseAddress);
}

// Overwatch's PE Header and .text section are combined into one, immutable memory region with 
// PAGE_EXECUTE_READ protection. This function copies Overwatch's mapped region into a remote
// buffer then writes the secret PE Header at the buffer's base. This buffer is the dump target.
duint fix_dump::current::BuildNewOverwatchRegion(const REMOTE_PE_HEADER& OverwatchPEHeader)
{
    LPVOID newOverwatchRegion = VirtualAllocEx(debuggee::hProcess,
                                               NULL,
                                               OverwatchPEHeader.optionalHeader->SizeOfImage,
                                               MEM_COMMIT,
                                               PAGE_EXECUTE_READWRITE);
    if (!newOverwatchRegion)
    {
        PluginLog("BuildNewOverwatchRegion: VirtualAllocEx failed %d.\n", GetLastError());
        return 0;
    }

    LPVOID transferBuffer = VirtualAlloc(NULL,
                                         OverwatchPEHeader.optionalHeader->SizeOfImage,
                                         MEM_COMMIT,
                                         PAGE_EXECUTE_READWRITE);
    if (!transferBuffer)
    {
        PluginLog("BuildNewOverwatchRegion: VirtualAlloc failed %d.\n", GetLastError());
        return 0;
    }

    if (const duint secretPEHeaderAddress = util::GetSecretPEHeaderBaseAddress())
    {
        if (memutil::RemoteRead(OverwatchPEHeader.remoteBaseAddress, transferBuffer, OverwatchPEHeader.optionalHeader->SizeOfImage) &&
            memutil::RemoteRead(secretPEHeaderAddress, transferBuffer, PE_HEADER_SIZE) &&
            //memutil::RemoteRead(secretPEHeaderAddress, transferBuffer, 0x400) &&
            memutil::RemoteWrite(duint(newOverwatchRegion), transferBuffer, OverwatchPEHeader.optionalHeader->SizeOfImage))
        {
            VirtualFree(transferBuffer, OverwatchPEHeader.optionalHeader->SizeOfImage, MEM_RELEASE);
            return duint(newOverwatchRegion);
        }
        else
            PluginLog("BuildNewOverwatchRegion: Failed to write transfer buffer to Overwatch.exe.\n");
    }
    else
        PluginLog("BuildNewOverwatchRegion: GetSecretPEHeaderBaseAddress failed.\n");

    VirtualFreeEx(debuggee::hProcess, newOverwatchRegion, OverwatchPEHeader.optionalHeader->SizeOfImage, MEM_RELEASE);
    VirtualFree(transferBuffer, OverwatchPEHeader.optionalHeader->SizeOfImage, MEM_RELEASE);
    return 0;
}

// Restore PE Header fields which were invalid in the secret PE Header.
bool fix_dump::current::RestorePEHeader(const REMOTE_PE_HEADER& OverwatchPEHeader, const REMOTE_PE_HEADER& NewRegionPEHeader)
{
    const duint imagebaseOffset = duint(&NewRegionPEHeader.optionalHeader->ImageBase) - duint(NewRegionPEHeader.dosHeader);
    return memutil::RemoteWrite(NewRegionPEHeader.remoteBaseAddress + imagebaseOffset,
                                PVOID(&NewRegionPEHeader.remoteBaseAddress),
                                sizeof(duint));
}

// Set correct page protection for the sections in the new Overwatch region.
void fix_dump::current::RestoreSectionProtection(const REMOTE_PE_HEADER& NewRegionPEHeader)
{
    auto setSectionProtection = [&](const char* SectionName, DWORD NewProtect)
    {
        if (PIMAGE_SECTION_HEADER section = GetSectionByName(NewRegionPEHeader, SectionName))
        {
            DWORD oldprot = 0;
            const duint baseAddress = NewRegionPEHeader.remoteBaseAddress + section->VirtualAddress;
            if (!VirtualProtectEx(debuggee::hProcess, PVOID(baseAddress), section->Misc.VirtualSize, NewProtect, &oldprot))
                PluginLog("Failed to restore section protection at %p.\n", baseAddress);
        }
        else
            PluginLog("RestoreSectionProtection error: %s is not a valid section.\n", SectionName);
    };

    // header
    DWORD oldprot = 0;
    if (!VirtualProtectEx(debuggee::hProcess, PVOID(NewRegionPEHeader.remoteBaseAddress), PE_HEADER_SIZE, PAGE_READONLY, &oldprot))
        PluginLog("Failed to restore section protection at %p.\n", NewRegionPEHeader.remoteBaseAddress);

    setSectionProtection(".text",   PAGE_EXECUTE_READ);
    setSectionProtection(".rdata",  PAGE_READONLY);
    setSectionProtection(".data",   PAGE_READWRITE);
    setSectionProtection(".pdata",  PAGE_READONLY);
    setSectionProtection(".tls",    PAGE_READWRITE);
    setSectionProtection("_RDATA",  PAGE_READONLY);
    setSectionProtection(".rsrc",   PAGE_READONLY);
    setSectionProtection(".reloc",  PAGE_READONLY);
}

// This is a hack to force Scylla to recognize the new Overwatch region in the "Pick Dll" drop
// down list. Create / write / insert a LDR_DATA_TABLE_ENTRY for this region into 
// PEB.Ldr.InMemoryOrderModuleList.
bool fix_dump::current::NoticeMeScylla(const REMOTE_PE_HEADER& NewRegionPEHeader)
{
    LPVOID remoteEntryAddress = VirtualAllocEx(debuggee::hProcess, NULL, sizeof(LDR_DATA_TABLE_ENTRY), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteEntryAddress)
    {
        PluginLog("NoticeMeScylla: VirtualAllocEx failed for remoteEntryAddress, %d.\n", GetLastError());
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
    memutil::RemoteRead(peb + FIELD_OFFSET(PEB, Ldr), &ldr, sizeof(duint));
    listHeadAddress = ldr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList);
    memutil::RemoteRead(listHeadAddress, &listHead, sizeof(LIST_ENTRY));

    // read Overwatch.exe's LDR_DATA_TABLE_ENTRY.
    memutil::RemoteRead(listHeadAddress, &listHeadFlink, sizeof(duint));
    overwatchEntryAddress = listHeadFlink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    memutil::RemoteRead(overwatchEntryAddress, &localModuleEntry, sizeof(localModuleEntry));

    // insert the new entry at the tail of InMemoryOrderModuleList.

    // Entry->Flink = ListHead;
    // Entry->Blink = PrevEntry;
    newEntry.Flink = PLIST_ENTRY(listHeadAddress);
    newEntry.Blink = listHead.Blink;

    // PrevEntry->Flink = Entry;
    const duint newEntryMemoryOrderLinks = duint(remoteEntryAddress) + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    memutil::RemoteWrite(duint(listHead.Blink), PVOID(&newEntryMemoryOrderLinks), sizeof(duint));

    // ListHead->Blink = Entry;
    memutil::RemoteWrite(listHeadAddress + sizeof(duint), &remoteEntryAddress, sizeof(duint));

    localModuleEntry.DllBase = PVOID(NewRegionPEHeader.remoteBaseAddress);
    localModuleEntry.EntryPoint = PVOID(NewRegionPEHeader.remoteBaseAddress + NewRegionPEHeader.optionalHeader->AddressOfEntryPoint);
    localModuleEntry.SizeOfImage = NewRegionPEHeader.optionalHeader->SizeOfImage;
    localModuleEntry.InMemoryOrderLinks = newEntry;

    if (!memutil::RemoteWrite(duint(remoteEntryAddress), &localModuleEntry, sizeof(localModuleEntry)))
    {
        PluginLog("NoticeMeScylla: RemoteWrite failed for localModuleEntry, %d.\n", GetLastError());
        return false;
    }
    
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// util

duint fix_dump::util::GetOverwatchImageBase()
{
    return DbgValFromString("overwatch.exe:0");
}

duint fix_dump::util::GetSecretPEHeaderBaseAddress()
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
                if (memutil::RemoteRead(duint(page->mbi.AllocationBase), PBYTE(&dosMagic), sizeof(dosMagic)))
                {
                    if (dosMagic == IMAGE_DOS_SIGNATURE)
                        return duint(page->mbi.AllocationBase);
                }
            }
        }
    }
    return 0;
}


////////////////////////////////////////////////////////////////////////////////
// winter_2016

namespace fix_dump {
namespace winter_2016 {
void FixOverwatch()
{
    if (!RestorePEHeader())
        return;

    REMOTE_PE_HEADER headerData;
    if (!FillRemotePEHeader(DbgGetProcessHandle, util::GetOverwatchImageBase(), headerData))
        return;

    if (!RebuildImports(headerData))
        return;

    if (!FixTextSection(headerData))
        return;

    PluginLog("exited successfully.\n");
}

// In one of the TLS callbacks Overwatch copies its PE Header into a memory region returned
// by VirtualAlloc.  It then fills the pe header at its imagebase with garbage data.
//
// This function locates the secret pe header, writes it to the pe header at overwatch's
// imagebase, then adjusts specific fields.
BOOL RestorePEHeader()
{
    const ULONG_PTR overwatchImageBase = util::GetOverwatchImageBase();
    const ULONG_PTR secretHeaderBaseAddress = util::GetSecretPEHeaderBaseAddress();

    if (!secretHeaderBaseAddress)
    {
        PluginLog("RestorePEHeader:  failed to locate secret PE Header.\n");
        return FALSE;
    }

    // the last 0x600 bytes of the secret header are garbage(?) 
    const SIZE_T REAL_PE_DATA_SIZE = 0x400;
    BYTE secretHeaderData[REAL_PE_DATA_SIZE];
    ZeroMemory(secretHeaderData, REAL_PE_DATA_SIZE);
    if (!DbgMemRead(secretHeaderBaseAddress, secretHeaderData, REAL_PE_DATA_SIZE))
    {
        PluginLog("RestorePEHeader:  failed to read secret PE Header at %p.\n", secretHeaderBaseAddress);
        return FALSE;
    }

    if (!DbgMemWrite(overwatchImageBase, secretHeaderData, REAL_PE_DATA_SIZE))
    {
        PluginLog("RestorePEHeader:  failed to patch overwatch.exe PE Header at %p.\n", overwatchImageBase);
        return FALSE;
    }

    /* individual field fixups */

    // IMAGE_OPTIONAL_HEADER64::ImageBase, offset = 0x18
    if (!DbgMemWrite(overwatchImageBase + 0x1B0, PBYTE(&overwatchImageBase), sizeof(overwatchImageBase)))
    {
        PluginLog("RestorePEHeader:  failed to patch Optional Header :: ImageBase at %p.\n", overwatchImageBase + 0x1B0);
        return FALSE;
    }

    return TRUE;
}

// The .text section is segmented by memory regions with PAGE_NOACCESS protection:
//      000000013F050000  0000000000001000  overwatch.exe                                                   MAP    -R--- ERW--
//      000000013F051000  00000000000C3000   ".text"                          Executable code               MAP    ER--- ERW--
//      000000013F114000  0000000000001000   ".text"                          Executable code               MAP    ----- ERW--
//      000000013F115000  0000000000002000   ".text"                          Executable code               MAP    ER--- ERW--
//      000000013F117000  0000000000003000   ".text"                          Executable code               MAP    ----- ERW--
//
// This function iterates over the .text section pages to set all pages with
// PAGE_NOACCESS protection to PAGE_EXECUTE_READ protection.  This causes
// x64dbg to view the entire section as one section without segmentation.
//
// This function fills the noaccess pages with 0xCC.  These pages probably
// contain encrypted code.  The current goal is to use IDA Pro to find code xrefs
// into noaccess pages in order to understand their behavior.
BOOL FixTextSection(const REMOTE_PE_HEADER& HeaderData)
{
    const PIMAGE_SECTION_HEADER textSection = GetSectionByName(HeaderData, ".text");
    const ULONG_PTR textSectionBase = HeaderData.remoteBaseAddress + textSection->VirtualAddress;
    const ULONG_PTR textSectionEnd = textSectionBase + textSection->Misc.VirtualSize;

    std::vector<MEMORY_BASIC_INFORMATION> textPages;
    if (!GetTextSectionPages(textSectionBase, textSectionEnd, textPages))
    {
        PluginLog("FixTextSection:  failed to get text section pages using range %p - %p.\n", textSectionBase, textSectionEnd);
        return FALSE;
    }

    // save the mbi for pages with PAGE_NOACCESS protection before combining
    std::vector<MEMORY_BASIC_INFORMATION> suspectPages;
    if (!CombineTextPages(textPages, suspectPages))
    {
        PluginLog("FixTextSection:  failed to combine text section pages.");
        return FALSE;
    }

    /* special case patching */

    // the first 'real' function in .text seems to start at an arbitrary offset.
    // this function calls 'InitializeCriticalSection'.
    // this value changed in the 12.13.2016 patch.
    //const duint firstFunctionOffset = 0xB2161;
    const duint firstFunctionOffset = 0xBFF80;
    if (!RemoveGarbageCode(textSectionBase, firstFunctionOffset))
    {
        PluginLog("FixTextSection:  failed to remove garbage code at %p (+%X)\n.", textSectionBase, firstFunctionOffset);
        return FALSE;
    }

    //plog("first function:  %p\n", textSectionBase + firstFunctionOffset);

    // fill the PAGE_NOACCESS pages with 0xCC.
    for (auto page : suspectPages)
    {
        if (!RemoveGarbageCode(ULONG_PTR(page.BaseAddress), page.RegionSize))
        {
            PluginLog("FixTextSection:  failed to remove garbage code for suspicious page at %p (%X)\n.", textSectionBase, firstFunctionOffset);
            return FALSE;
        }
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////
// utils

BOOL GetTextSectionPages(ULONG_PTR TextBaseAddress, ULONG_PTR TextEndAddress, OUT std::vector<MEMORY_BASIC_INFORMATION>& TextPages)
{
    MEMMAP memmap;
    if (!DbgMemMap(&memmap))
        return FALSE;

    int i = 0;
    while (i < memmap.count)
    {
        MEMPAGE* page = &memmap.page[i];
        if (page->mbi.BaseAddress == PVOID(TextBaseAddress))
        {
            TextPages.push_back(page->mbi);
            i++;
            while (i < memmap.count)
            {
                page = &memmap.page[i];
                if (page->mbi.BaseAddress >= PVOID(TextEndAddress))
                    return TRUE;
                TextPages.push_back(page->mbi);
                i++;
            }
        }
        i++;
    }
    return FALSE;
}

BOOL CombineTextPages(const std::vector<MEMORY_BASIC_INFORMATION>& TextPages, OUT std::vector<MEMORY_BASIC_INFORMATION>& SuspectPages)
{
    const HANDLE hProcess = DbgGetProcessHandle();
    for (auto page : TextPages)
    {
        if (page.Protect == PAGE_NOACCESS)
        {
            DWORD useless;
            SuspectPages.push_back(page);
            if (!VirtualProtectEx(hProcess, page.BaseAddress, page.RegionSize, PAGE_EXECUTE_READ, &useless))
                return FALSE;
        }
    }
    return TRUE;
}

BOOL RemoveGarbageCode(ULONG_PTR BaseAddress, SIZE_T RegionSize)
{
    const HANDLE hProcess = DbgGetProcessHandle();
    BOOL status = FALSE;
    DWORD oldprot;
    if (VirtualProtectEx(hProcess, LPVOID(BaseAddress), RegionSize, PAGE_EXECUTE_READWRITE, &oldprot))
    {
        PBYTE cc = new BYTE[RegionSize];
        FillMemory(cc, RegionSize, 0xCC);
        if (DbgMemWrite(BaseAddress, cc, RegionSize))
        {
            DWORD useless;
            if (VirtualProtectEx(hProcess, LPVOID(BaseAddress), RegionSize, oldprot, &useless))
                status = TRUE;
        }
        delete[] cc;
    }
    return status;
}

////////////////////////////////////////////////////////////////////////////////
// address getters

ULONG_PTR GetOverwatchImageBase()
{
    return DbgValFromString("overwatch.exe:0");
}

ULONG_PTR GetSecretPEHeaderBaseAddress()
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
                if (DbgMemRead(ULONG_PTR(page->mbi.AllocationBase), PBYTE(&dosMagic), sizeof(dosMagic)))
                {
                    if (dosMagic == IMAGE_DOS_SIGNATURE)
                        return ULONG_PTR(page->mbi.AllocationBase);
                }
            }
        }
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
// debug

void DumpPages(const std::vector<MEMORY_BASIC_INFORMATION>& Pages)
{
    for (auto page : Pages)
        PLOG("%p  %llX  %X\n", page.BaseAddress, page.RegionSize, page.Protect);
}

} // namespace winter_2016
} // namespace fix_dump
