#include "pe_header.h"

////////////////////////////////////////////////////////////////////////////////
// ctors

bool FillPEHeader(ULONG_PTR BaseAddress, OUT PE_HEADER& PEHeader)
{
    if (!IsValidPEHeader(BaseAddress))
        return false;
    PEHeader.dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    PEHeader.ntHeaders = PIMAGE_NT_HEADERS64(ULONG_PTR(PEHeader.dosHeader) + PEHeader.dosHeader->e_lfanew);
    PEHeader.fileHeader = PIMAGE_FILE_HEADER(&PEHeader.ntHeaders->FileHeader);
    PEHeader.optionalHeader = PIMAGE_OPTIONAL_HEADER64(&PEHeader.ntHeaders->OptionalHeader);
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        PEHeader.dataDirectory[i] = &PEHeader.ntHeaders->OptionalHeader.DataDirectory[i];
    const ULONG_PTR firstSectionHeader = ULONG_PTR(IMAGE_FIRST_SECTION(PEHeader.ntHeaders));
    for (int i = 0; i < PEHeader.fileHeader->NumberOfSections; i++)
        PEHeader.sectionHeader.push_back(PIMAGE_SECTION_HEADER(i * sizeof(IMAGE_SECTION_HEADER) + firstSectionHeader));
    return true;
}

bool FillRemotePEHeader(HANDLE ProcessHandle, ULONG_PTR BaseAddress, OUT REMOTE_PE_HEADER& PEHeader)
{
    ZeroMemory(PEHeader.rawData, PE_HEADER_SIZE);
    if (!ReadProcessMemory(ProcessHandle, PVOID(BaseAddress), PEHeader.rawData, PE_HEADER_SIZE, NULL))
        return false;
    if (!FillPEHeader(ULONG_PTR(&PEHeader.rawData), PEHeader))
        return false;
    PEHeader.remoteBaseAddress = BaseAddress;
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// utils

bool IsValidPEHeader(ULONG_PTR BaseAddress)
{
    if (!BaseAddress) return false;
    PIMAGE_DOS_HEADER dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS64 ntHeader = PIMAGE_NT_HEADERS64(BaseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;
    PIMAGE_OPTIONAL_HEADER64 optionalHeader = PIMAGE_OPTIONAL_HEADER64(&ntHeader->OptionalHeader);
    if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    return true;
}

const PIMAGE_SECTION_HEADER GetSectionByName(const PE_HEADER& HeaderData, const char* SectionName)
{
    for (auto section : HeaderData.sectionHeader)
        if (!strncmp(PCHAR(section->Name), SectionName, 8))
            return section;
    return 0;
}
