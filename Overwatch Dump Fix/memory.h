#pragma once

#include <Windows.h>
#include <vector>

namespace memory {

bool RemapViewOfSection(SIZE_T BaseAddress, SIZE_T RegionSize);
bool CombineAdjacentViews(const std::vector<MEMORY_BASIC_INFORMATION>& Views);

namespace util {
bool RemoteWrite(SIZE_T BaseAddress, PVOID SourceAddress, SIZE_T WriteSize);
bool RemoteRead(SIZE_T BaseAddress, const PVOID DestinationAddress, SIZE_T ReadSize);
bool GetPageInfo(SIZE_T BaseAddress,
                 SIZE_T RegionSize,
                 std::vector<MEMORY_BASIC_INFORMATION>& PageInfo);
} // namespace util

} // namespace memory