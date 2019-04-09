#pragma once

#include <Windows.h>

_Check_return_
BOOL
AduRevertPatchNtdllDbgBreakPoint(
    _In_ HANDLE hProcess
);
