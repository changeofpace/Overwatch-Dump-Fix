#include "fix_dump.h"
#include "ow_imports.h"

////////////////////////////////////////////////////////////////////////////////
// main

VOID FixOverwatch()
{
    if (!RestorePEHeader())
        return;

    REMOTE_PE_HEADER_DATA headerData;
    if (!FillPEHeaderData(GetOverwatchImageBase(), headerData))
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
    const ULONG_PTR overwatchImageBase = GetOverwatchImageBase();
    const ULONG_PTR secretHeaderBaseAddress = GetSecretPEHeaderBaseAddress();

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
BOOL FixTextSection(const REMOTE_PE_HEADER_DATA& HeaderData)
{
    const PIMAGE_SECTION_HEADER textSection = GetSectionByName(HeaderData, ".text");
    const ULONG_PTR textSectionBase = HeaderData.baseAddress + textSection->VirtualAddress;
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
    for (auto page : TextPages)
    {
        if (page.Protect == PAGE_NOACCESS)
        {
            DWORD useless;
            SuspectPages.push_back(page);
            if (!VirtualProtectEx(global::hProcess, page.BaseAddress, page.RegionSize, PAGE_EXECUTE_READ, &useless))
                return FALSE;
        }
    }
    return TRUE;
}

BOOL RemoveGarbageCode(ULONG_PTR BaseAddress, SIZE_T RegionSize)
{
    BOOL status = FALSE;
    DWORD oldprot;
    if (VirtualProtectEx(global::hProcess, LPVOID(BaseAddress), RegionSize, PAGE_EXECUTE_READWRITE, &oldprot))
    {
        PBYTE cc = new BYTE[RegionSize];
        FillMemory(cc, RegionSize, 0xCC);
        if (DbgMemWrite(BaseAddress, cc, RegionSize))
        {
            DWORD useless;
            if (VirtualProtectEx(global::hProcess, LPVOID(BaseAddress), RegionSize, oldprot, &useless))
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

VOID DumpPages(const std::vector<MEMORY_BASIC_INFORMATION>& Pages)
{
    for (auto page : Pages)
        plog("%p  %llX  %X\n", page.BaseAddress, page.RegionSize, page.Protect);
}