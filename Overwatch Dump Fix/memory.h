#pragma once

#include <Windows.h>
#include <vector>

namespace memory {

bool RemapViewOfSection(SIZE_T BaseAddress, SIZE_T RegionSize);
bool CombineAdjacentViews(const std::vector<MEMORY_BASIC_INFORMATION>& Views);

namespace util {
bool RemoteWrite(SIZE_T BaseAddress, PVOID DestinationAddress, SIZE_T WriteSize);
bool RemoteRead(SIZE_T BaseAddress, const PVOID SourceAddress, SIZE_T ReadSize);
bool GetPageInfo(SIZE_T BaseAddress,
                 SIZE_T RegionSize,
                 std::vector<MEMORY_BASIC_INFORMATION>& PageInfo);
SIZE_T RoundUpToAllocationGranularity(SIZE_T Size);
SIZE_T AlignToAllocationGranularity(SIZE_T Address);
} // namespace util

} // namespace memory