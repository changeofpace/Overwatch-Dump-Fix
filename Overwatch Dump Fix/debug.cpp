#include "debug.h"

#include "plugin.h"

static const char* dbgDelim = "==============================================================================\n";

void plugindbg::DumpMemoryBasicInformation(const MEMORY_BASIC_INFORMATION& Mbi)
{
    PLOG(dbgDelim);
    PLOG("MEMORY_BASIC_INFORMATION\n");
    PLOG(dbgDelim);
    PLOG("    BaseAddress:         %p\n", Mbi.BaseAddress);
    PLOG("    AllocationBase:      %p\n", Mbi.AllocationBase);
    PLOG("    AllocationProtect:   %016X\n", Mbi.AllocationProtect);
    PLOG("    RegionSize:          %016X\n", Mbi.RegionSize);
    PLOG("    State:               %16X\n", Mbi.State);
    PLOG("    Protect:             %16X\n", Mbi.Protect);
    PLOG("    Type:                %16X\n", Mbi.Type);
    PLOG("\n");
}


void plugindbg::DumpMemoryBasicInformationShort(const MEMORY_BASIC_INFORMATION& Mbi)
{
    PLOG("base: %p    size: %16llX    prot: %8X   init prot: %8X\n", Mbi.BaseAddress, Mbi.RegionSize, Mbi.Protect, Mbi.AllocationProtect);
}
