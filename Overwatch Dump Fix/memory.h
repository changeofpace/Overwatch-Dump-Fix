#pragma once

#include <Windows.h>
#include <vector>

namespace memory {

bool RemapViewOfSection(size_t base_address, size_t region_size);
bool CombineAdjacentViews(const std::vector<MEMORY_BASIC_INFORMATION>& Views);

namespace util {
bool RemoteWrite(SIZE_T BaseAddress, PVOID DestinationAddress, SIZE_T WriteSize);
bool RemoteRead(SIZE_T BaseAddress, const PVOID SourceAddress, SIZE_T ReadSize);
bool GetPageInfo(size_t base_address,
                 size_t range_size,
                 std::vector<MEMORY_BASIC_INFORMATION>& page_info);
SIZE_T RoundUpToAllocationGranularity(SIZE_T Size);
SIZE_T AlignToAllocationGranularity(SIZE_T Address);
} // namespace util

} // namespace memory