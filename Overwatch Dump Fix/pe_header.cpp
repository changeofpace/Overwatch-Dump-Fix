#include "pe_header.h"

BUFFERED_PE_HEADER::BUFFERED_PE_HEADER()
{
    raw_data = new BYTE[PE_HEADER_SIZE];
}

BUFFERED_PE_HEADER::~BUFFERED_PE_HEADER()
{
    delete[] raw_data;
}

///////////////////////////////////////////////////////////////////////////////
// fill ctors

bool FillPeHeader(SIZE_T BaseAddress, PE_HEADER& PeHeader)
{
    if (!IsValidPeHeader(BaseAddress))
        return false;
    PeHeader.dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    PeHeader.ntHeaders = PIMAGE_NT_HEADERS(SIZE_T(PeHeader.dosHeader) +
                                           PeHeader.dosHeader->e_lfanew);
    PeHeader.fileHeader = PIMAGE_FILE_HEADER(&PeHeader.ntHeaders->FileHeader);
    PeHeader.optionalHeader = PIMAGE_OPTIONAL_HEADER(&PeHeader.ntHeaders->OptionalHeader);
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        PeHeader.dataDirectory[i] = &PeHeader.ntHeaders->OptionalHeader.DataDirectory[i];
    const SIZE_T firstSectionHeader = SIZE_T(IMAGE_FIRST_SECTION(PeHeader.ntHeaders));
    for (int i = 0; i < PeHeader.fileHeader->NumberOfSections; i++)
        PeHeader.sectionHeaders.push_back(PIMAGE_SECTION_HEADER(i * sizeof(IMAGE_SECTION_HEADER) + firstSectionHeader));
    return true;
}

bool FillBufferedPeHeader(const PBYTE PeBuffer, SIZE_T BufferSize,
                          BUFFERED_PE_HEADER& PeHeader)
{
    if (!PeBuffer || BufferSize != PE_HEADER_SIZE)
        return false;
    memcpy(PeHeader.raw_data, PeBuffer, PE_HEADER_SIZE);
    return FillPeHeader(SIZE_T(PeHeader.raw_data), PeHeader);
}

bool FillRemotePeHeader(HANDLE ProcessHandle, SIZE_T BaseAddress,
                        REMOTE_PE_HEADER& PeHeader)
{
    ZeroMemory(PeHeader.raw_data, PE_HEADER_SIZE);
    if (!ReadProcessMemory(ProcessHandle, PVOID(BaseAddress), PeHeader.raw_data,
                           PE_HEADER_SIZE, nullptr))
        return false;
    if (!FillPeHeader(SIZE_T(PeHeader.raw_data), PeHeader))
        return false;
    PeHeader.remoteBaseAddress = BaseAddress;
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// utils

bool IsValidPeHeader(SIZE_T BaseAddress)
{
    if (!BaseAddress) return false;
    PIMAGE_DOS_HEADER dosHeader = PIMAGE_DOS_HEADER(BaseAddress);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS(BaseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;
    PIMAGE_OPTIONAL_HEADER optionalHeader = PIMAGE_OPTIONAL_HEADER(&ntHeader->OptionalHeader);
    if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    return true;
}

DWORD GetSizeOfImage(PVOID BaseAddress)
{
    if (!IsValidPeHeader(SIZE_T(BaseAddress)))
        return 0;
    return PIMAGE_NT_HEADERS(SIZE_T(BaseAddress) +
        PIMAGE_DOS_HEADER(BaseAddress)->e_lfanew)->OptionalHeader.SizeOfImage;
}

PIMAGE_SECTION_HEADER GetPeSectionByName(const PE_HEADER& HeaderData,
                                         const char* SectionName)
{
    for (auto section : HeaderData.sectionHeaders) {
        if (!strncmp(PCHAR(section->Name), SectionName, 8))
            return section;
    }
    return 0;
}



