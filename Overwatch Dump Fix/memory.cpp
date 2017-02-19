#include "memory.h"

#include <vector>

#include "ntapi.h"
#include "plugin.h"

static bool _RemapViewOfSection(SIZE_T BaseAddress,
                                SIZE_T RegionSize,
                                PVOID CopyBuffer,
                                std::vector<SIZE_T>* ReplacedViewBases = nullptr)
{
    // Backup the view's content.
    if (!memory::util::RemoteRead(BaseAddress, CopyBuffer, RegionSize))
    {
        PluginLog("Error: failed to backup view at %p: %d.\n",
                  BaseAddress,
                  GetLastError());
        return false;
    }

    // Create a section to store the remapped view.
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionMaxSize = {};
    sectionMaxSize.QuadPart = RegionSize;
    ntapi::NTSTATUS status = ntapi::NtCreateSection(&hSection,
                                                    SECTION_ALL_ACCESS,
                                                    NULL,
                                                    &sectionMaxSize,
                                                    PAGE_EXECUTE_READWRITE,
                                                    SEC_COMMIT,
                                                    NULL);
    if (status != ntapi::STATUS_SUCCESS)
    {
        PluginLog("Error: NtCreateSection failed for %p, %llX:  0x%08X\n",
                  BaseAddress,
                  RegionSize,
                  status);
        return false;
    }

    const std::vector<SIZE_T> replacedViewBases = ReplacedViewBases ?
                                                  *ReplacedViewBases :
                                                  std::vector<SIZE_T>{BaseAddress};

    // Unmap the existing view(s).
    for (const auto view : replacedViewBases)
    {
        status = ntapi::NtUnmapViewOfSection(debuggee::hProcess, PVOID(view));
        if (status != ntapi::STATUS_SUCCESS)
        {
            PluginLog("Error: NtUnmapViewOfSection failed for %p:  0x%08X\n",
                      view,
                      status);
            return false;
        }
    }

    // Map the new view.
    PVOID viewBase = PVOID(BaseAddress);
    LARGE_INTEGER sectionOffset = {};
    SIZE_T viewSize = 0;
    status = ntapi::NtMapViewOfSection(hSection,
                                       debuggee::hProcess,
                                       &viewBase,
                                       0,
                                       RegionSize,
                                       &sectionOffset,
                                       &viewSize,
                                       ntapi::ViewUnmap,
                                       0,
                                       PAGE_EXECUTE_READWRITE);
    if (status != ntapi::STATUS_SUCCESS)
    {
        PluginLog("Error: NtMapViewOfSection failed for %p, %llX:  0x%08X\n",
                  BaseAddress,
                  RegionSize,
                  status);
        return false;
    }

    // Restore the view's content.
    if (!memory::util::RemoteWrite(BaseAddress, CopyBuffer, RegionSize))
    {
        PluginLog("Error: failed to restore view at %p: %d.\n",
                  BaseAddress,
                  GetLastError());
        return false;
    }

    return true;
}

bool memory::RemapViewOfSection(SIZE_T BaseAddress, SIZE_T RegionSize)
{
    PVOID copybuf = VirtualAlloc(NULL, RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!copybuf)
        return false;
    bool result = _RemapViewOfSection(BaseAddress, RegionSize, copybuf);
    VirtualFree(copybuf, 0, MEM_RELEASE);
    return result;
}

bool memory::CombineAdjacentViews(const std::vector<MEMORY_BASIC_INFORMATION>& Views)
{
    // Check for consecutive views.
    SIZE_T combinedSize = 0;
    std::vector<SIZE_T> replacedViewBases;
    for (int i = 0; i < Views.size(); i++)
    {
        if (combinedSize && SIZE_T(Views[i - 1].BaseAddress) + combinedSize != SIZE_T(Views[i].BaseAddress))
        {
            PluginLog("Error: attempted to combine non-consecutive views.\n");
            return false;
        }
        combinedSize += Views[i].RegionSize;
        replacedViewBases.push_back(SIZE_T(Views[i].BaseAddress));
    }
    PVOID copybuf = VirtualAlloc(NULL, combinedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!copybuf)
        return false;
    bool result = _RemapViewOfSection(SIZE_T(Views[0].BaseAddress), combinedSize, copybuf, &replacedViewBases);
    VirtualFree(copybuf, 0, MEM_RELEASE);
    return result;
}

///////////////////////////////////////////////////////////////////////////////
// util

bool memory::util::RemoteWrite(SIZE_T BaseAddress, PVOID SourceAddress, SIZE_T WriteSize)
{
    SIZE_T numberOfBytesWritten = 0;
    ntapi::NTSTATUS status = ntapi::NtWriteVirtualMemory(debuggee::hProcess,
                                                         PVOID(BaseAddress),
                                                         SourceAddress,
                                                         WriteSize,
                                                         &numberOfBytesWritten);
    return status == ntapi::STATUS_SUCCESS && numberOfBytesWritten == WriteSize;
}

bool memory::util::RemoteRead(SIZE_T BaseAddress, const PVOID DestinationAddress, SIZE_T ReadSize)
{
    SIZE_T numberOfBytesRead = 0;
    ntapi::NTSTATUS status = ntapi::NtReadVirtualMemory(debuggee::hProcess,
                                                        PVOID(BaseAddress),
                                                        DestinationAddress,
                                                        ReadSize,
                                                        &numberOfBytesRead);
    return status == ntapi::STATUS_SUCCESS && numberOfBytesRead == ReadSize;
}


bool memory::util::GetPageInfo(SIZE_T BaseAddress,
                               SIZE_T RegionSize,
                               std::vector<MEMORY_BASIC_INFORMATION>& PageInfo)
{
    const SIZE_T endAddress = BaseAddress + RegionSize;
    for (SIZE_T ea = BaseAddress; ea < endAddress;)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(debuggee::hProcess, PVOID(ea), &mbi, sizeof(mbi)))
            return false;
        PageInfo.push_back(mbi);
        ea += mbi.RegionSize;
    }
    return true;
}