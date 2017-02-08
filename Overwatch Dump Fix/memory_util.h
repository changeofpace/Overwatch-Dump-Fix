#pragma once

#include <Windows.h>

// WriteProcessMemory and ReadProcessMemory wrappers.
namespace memutil {
bool RemoteWrite(ULONG_PTR BaseAddress, const PVOID SourceAddress, SIZE_T WriteSize);
bool RemoteRead(ULONG_PTR BaseAddress, const PVOID DestinationAddress, SIZE_T ReadSize);
} // namespace memutil