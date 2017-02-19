#pragma once

#include <Windows.h>

#include "pe_header.h"

namespace owimports {

// This function iterates over the iat, resolves each thunk to the import's
// real virtual address, then patches the iat with the resolved import array.
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] is patched to point to .rdata's base
// address.
bool RebuildImports(const REMOTE_PE_HEADER& HeaderData);

} // namespace owimports