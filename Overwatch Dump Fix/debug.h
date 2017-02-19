#pragma once

#include <Windows.h>

namespace plugindbg {
void DumpMemoryBasicInformation(const MEMORY_BASIC_INFORMATION& Mbi);
void DumpMemoryBasicInformationShort(const MEMORY_BASIC_INFORMATION& Mbi);
} // namespace plugindbg