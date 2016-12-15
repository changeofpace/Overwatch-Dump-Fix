#pragma once

#include <Windows.h>
#include <array>
#include <vector>

////////////////////////////////////////////////////////////////////////////////
// constants

const DWORD PE_HEADER_SIZE = 0x1000;

////////////////////////////////////////////////////////////////////////////////
// types

typedef struct _REMOTE_PE_HEADER_DATA {
    ULONG_PTR baseAddress;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeader;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_OPTIONAL_HEADER64 optionalHeader;
    std::array<PIMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> dataDirectory;
    std::vector<PIMAGE_SECTION_HEADER> sectionHeaders;
    
    BYTE rawData[PE_HEADER_SIZE];
} REMOTE_PE_HEADER_DATA;

////////////////////////////////////////////////////////////////////////////////
// ctors

BOOL FillPEHeaderData(ULONG_PTR BaseAddress, OUT REMOTE_PE_HEADER_DATA& PEHeader);

////////////////////////////////////////////////////////////////////////////////
// utils

BOOL IsValidPEHeader(ULONG_PTR BaseAddress);
ULONG_PTR GetSectionVirtualAddressByName(const REMOTE_PE_HEADER_DATA& HeaderData, const char* SectionName);
const PIMAGE_SECTION_HEADER GetSectionByName(const REMOTE_PE_HEADER_DATA& HeaderData, const char* SectionName);