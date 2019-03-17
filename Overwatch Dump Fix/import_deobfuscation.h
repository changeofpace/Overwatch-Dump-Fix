#pragma once

#include <Windows.h>

#include "pe_header.h"

_Check_return_
BOOL
IdfDeobfuscateImportAddressTable(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ ULONG cbImageSize,
    _In_ const REMOTE_PE_HEADER& RemotePeHeader
);
