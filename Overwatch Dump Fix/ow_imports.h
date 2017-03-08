#pragma once

#include <Windows.h>

#include "pe_header.h"

typedef size_t csh;
struct cs_insn;

namespace owimports {

// 3.6.2017: imports are spread across several 0x1000 byte regions and the thunks
// now contain jumps to inside the region. This now uses capstone disassembler to
// unpack the thunks.
//
// 00000000048506E9 | movabs  rax, 7FED0D52A28
// 00000000048506F3 | sub     rax, 251F684C
// 00000000048506F9 | jmp     4850FB3
// 0000000004850FB3 | add     rax, 13188D39
// 0000000004850FB9 | add     rax, 590B8D0
// 0000000004850FBF | jmp     48507A5
// ...
// 0000000004850501 | jmp     rax
class ImportUnpacker
{
public:
    ~ImportUnpacker();
    bool initialize();
    SIZE_T resolve(SIZE_T ThunkBase);

private:
    bool resolveBlock(const unsigned char * CodeBuf, SIZE_T CodeSize, SIZE_T & EA, SIZE_T & Import);

private:
    csh hCapstone;
    cs_insn* insn;
};

// This function iterates over the iat, resolves each thunk to the import's
// real virtual address, then patches the iat with the resolved import array.
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] is patched to point to .rdata's base
// address.
bool RebuildImports(const REMOTE_PE_HEADER& HeaderData);

} // namespace owimports