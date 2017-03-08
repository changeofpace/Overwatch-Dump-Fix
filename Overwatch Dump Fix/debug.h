#pragma once

#include <Windows.h>

typedef size_t csh;
struct cs_insn;

namespace plugindbg {

const char* const delimMajor =
    "==============================================================================\n";
const char* const delimMinor =
    "------------------------------------------------------------------------------\n";

void DumpMemoryBasicInformation(const MEMORY_BASIC_INFORMATION & Mbi);
void DumpMemoryBasicInformationShort(const MEMORY_BASIC_INFORMATION & Mbi);
void DumpCapstoneInsn(csh hCapstone, const cs_insn * Insn, size_t RemoteAddress = 0);
} // namespace plugindbg