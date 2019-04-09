#include "memory.h"

#include <vector>

#include "ntdll.h"
#include "plugin.h"

static DWORD systemAllocationGranularity = 0;

static void SetSystemAllocationGranularity()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    systemAllocationGranularity = si.dwAllocationGranularity;
}

static bool _RemapViewOfSection(SIZE_T BaseAddress, SIZE_T RegionSize, PVOID CopyBuffer,
                                std::vector<SIZE_T>* ReplacedViewBases = nullptr)
{
    // Backup the view's content.
    if (!memory::util::RemoteRead(BaseAddress, CopyBuffer, RegionSize)) {
        pluginLog("Error: failed to backup view at %p: %d.\n", BaseAddress,
                  GetLastError());
        return false;
    }

    // Create a section to store the remapped view.
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionMaxSize = {};
    sectionMaxSize.QuadPart = RegionSize;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionMaxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (!NT_SUCCESS(status)) {
        pluginLog("Error: NtCreateSection failed for %p, %llX:  0x%08X\n",
                  BaseAddress, RegionSize, status);
        return false;
    }

    const std::vector<SIZE_T> replacedViewBases = ReplacedViewBases ?
                                                  *ReplacedViewBases :
                                                  std::vector<SIZE_T>{BaseAddress};

    // Unmap the existing view(s).
    for (const auto view : replacedViewBases) {
        status = NtUnmapViewOfSection(debuggee.hProcess, PVOID(view));
        if (!NT_SUCCESS(status)) {
            pluginLog("Error: NtUnmapViewOfSection failed for %p:  0x%08X\n",
                      view, status);
            return false;
        }
    }

    // Map the new view.
    PVOID viewBase = PVOID(BaseAddress);
    LARGE_INTEGER sectionOffset = {};
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection,
                                debuggee.hProcess,
                                &viewBase,
                                0,
                                RegionSize,
                                &sectionOffset,
                                &viewSize,
                                ViewUnmap,
                                0,
                                PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        pluginLog("Error: NtMapViewOfSection failed for %p, %llX:  0x%08X\n",
                  BaseAddress, RegionSize, status);
        return false;
    }

    // Restore the view's content.
    if (!memory::util::RemoteWrite(BaseAddress, CopyBuffer, RegionSize)) {
        pluginLog("Error: failed to restore view at %p: %d.\n",
                  BaseAddress, GetLastError());
        return false;
    }

    return true;
}

bool memory::RemapViewOfSection(size_t base_address, size_t region_size) {
    PVOID copy_buffer = VirtualAlloc(NULL,
                                     region_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!copy_buffer)
        return false;
    bool result = _RemapViewOfSection(base_address, region_size, copy_buffer);
    VirtualFree(copy_buffer, 0, MEM_RELEASE);
    return result;
}

//bool memory::CombineAdjacentViews(const std::vector<MEMORY_BASIC_INFORMATION>& Views)
//{
//    // Check for consecutive views.
//    SIZE_T combinedSize = 0;
//    std::vector<SIZE_T> replacedViewBases;
//    for (int i = 0; i < Views.size(); i++) {
//        if (combinedSize && SIZE_T(Views[i - 1].BaseAddress) + combinedSize != SIZE_T(Views[i].BaseAddress)) {
//            pluginLog("Error: attempted to combine non-consecutive views.\n");
//            return false;
//        }
//        combinedSize += Views[i].RegionSize;
//        replacedViewBases.push_back(SIZE_T(Views[i].BaseAddress));
//    }
//    PVOID copybuf = VirtualAlloc(NULL, combinedSize, MEM_COMMIT | MEM_RESERVE,
//                                 PAGE_EXECUTE_READWRITE);
//    if (!copybuf)
//        return false;
//    bool result = _RemapViewOfSection(SIZE_T(Views[0].BaseAddress), combinedSize,
//                                      copybuf, &replacedViewBases);
//    VirtualFree(copybuf, 0, MEM_RELEASE);
//    return result;
//}

///////////////////////////////////////////////////////////////////////////////
// util

bool memory::util::RemoteWrite(SIZE_T BaseAddress, PVOID DestinationAddress,
                               SIZE_T WriteSize)
{
    SIZE_T numberOfBytesWritten = 0;
    NTSTATUS status = NtWriteVirtualMemory(
        debuggee.hProcess,
        PVOID(BaseAddress),
        DestinationAddress,
        WriteSize,
        &numberOfBytesWritten);
    return status == STATUS_SUCCESS && numberOfBytesWritten == WriteSize;
}

bool memory::util::RemoteRead(SIZE_T BaseAddress, const PVOID SourceAddress,
                              SIZE_T ReadSize)
{
    SIZE_T numberOfBytesRead = 0;
    NTSTATUS status = NtReadVirtualMemory(
        debuggee.hProcess,
        PVOID(BaseAddress),
        SourceAddress,
        ReadSize,
        &numberOfBytesRead);
    return status == STATUS_SUCCESS && numberOfBytesRead == ReadSize;
}

bool memory::util::GetPageInfo(size_t base_address, size_t range_size,
                               std::vector<MEMORY_BASIC_INFORMATION>& page_info)
{
    page_info.clear();
    const size_t end_address = base_address + range_size;
    for (size_t ea = base_address; ea < end_address; /**/) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(debuggee.hProcess, PVOID(ea), &mbi, sizeof(mbi)))
            return false;
        page_info.push_back(mbi);
        ea += mbi.RegionSize;
    }
    return page_info.size() > 0;
}

SIZE_T memory::util::RoundUpToAllocationGranularity(SIZE_T Size)
{
    if (!systemAllocationGranularity)
        SetSystemAllocationGranularity();
    return ((Size + systemAllocationGranularity - 1) &
            ~(systemAllocationGranularity - 1));
}

SIZE_T memory::util::AlignToAllocationGranularity(SIZE_T Address)
{
    if (!systemAllocationGranularity)
        SetSystemAllocationGranularity();
    return (Address & ~(systemAllocationGranularity - 1));
}
