#include "anti_debug_util.h"

#include "plugin.h"


#define INSN_SOFTWARE_BREAKPOINT    0xCC


//
// AduRevertPatchNtdllDbgBreakPoint
//
// This function reverts the instruction at ntdll!DbgBreakPoint in the
//  specified process if it has been modified.
//
// On Windows 7 x64, the function body of ntdll!DbgBreakPoint is a software
//  breakpoint instruction (0xCC) followed by a return instruction (0xC3):
//
//        ntdll!DbgBreakPoint:
//        00000000`76e5b1d0     cc      int 3
//        00000000`76e5b1d1     c3      ret
//
// If this software breakpoint instruction is patched at runtime then user mode
//  debuggers will be unable to attach to the target process (i.e., the process
//  which has a private physical page mapped for the modified page because of
//  Copy-On-Write protection) via kernel32!DebugActiveProcess. This effectively
//  prevents the target process from being debugged by user mode code.
//
// NOTE This function does not suspend the target process / threads in the
//  target process.
//
_Use_decl_annotations_
BOOL
AduRevertPatchNtdllDbgBreakPoint(
    HANDLE hProcess
)
{
    HMODULE hNtdll = NULL;
    PVOID pDbgBreakPoint = NULL;
    BYTE Instruction = 0;
    DWORD PreviousProtection = 0;
    BOOLEAN fRestorePageProtection = FALSE;
    BYTE SoftwareBreakpointInstruction = 0xCC;
    BOOL status = TRUE;

    INF_PRINT("Reverting ntdll.DbgBreakPoint patch.\n");

    //
    // Locate the address of ntdll!DbgBreakPoint inside the executing process.
    //
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        ERR_PRINT("GetModuleHandleW failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // TODO Obtain the base address of ntdll.lib from the ntdll PEB_LDR_DATA
    //  entry instead.
    //
    pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
    if (!pDbgBreakPoint)
    {
        ERR_PRINT("GetProcAddress failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    INF_PRINT("Found ntdll.DbgBreakPoint: %p\n", pDbgBreakPoint);

    //
    // ntdll.dll is always loaded at the same base address in every process so
    //  read the byte at the address of ntdll!DbgBreakPoint in the virtual
    //  address space of the target process.
    //
    status = ReadProcessMemory(
        hProcess,
        pDbgBreakPoint,
        &Instruction,
        sizeof(Instruction),
        NULL);
    if (!status)
    {
        ERR_PRINT("ReadProcessMemory failed: %u (lpBaseAddress = %p)\n",
            GetLastError(),
            pDbgBreakPoint);
        goto exit;
    }

    //
    // If the byte is '0xCC' then there is no work to be done.
    //
    if (INSN_SOFTWARE_BREAKPOINT == Instruction)
    {
        INF_PRINT("ntdll.DbgBreakPoint is currently '0xCC'.\n");
        goto exit;
    }

    INF_PRINT(
        "ntdll.DbgBreakPoint is currently '0x%hhX', patching it to '0xCC'.\n",
        Instruction);
    
    //
    // Patch the byte to '0xCC'.
    //
    status = VirtualProtectEx(
        hProcess,
        pDbgBreakPoint,
        sizeof(Instruction),
        PAGE_EXECUTE_READWRITE,
        &PreviousProtection);
    if (!status)
    {
        ERR_PRINT(
            "VirtualProtectEx failed: %u (lpAddress = %p, flNewProtect = 0x%X)\n",
            GetLastError(),
            pDbgBreakPoint,
            PAGE_EXECUTE_READWRITE);
        goto exit;
    }
    //
    fRestorePageProtection = TRUE;

    status = WriteProcessMemory(
        hProcess,
        pDbgBreakPoint,
        &SoftwareBreakpointInstruction,
        sizeof(SoftwareBreakpointInstruction),
        NULL);
    if (!status)
    {
        ERR_PRINT("WriteProcessMemory failed: %u (lpBaseAddress = %p)\n",
            GetLastError(),
            pDbgBreakPoint);
        goto exit;
    }

exit:
    if (fRestorePageProtection)
    {
        BOOL UnwindStatus = VirtualProtectEx(
            hProcess,
            pDbgBreakPoint,
            sizeof(Instruction),
            PreviousProtection,
            &PreviousProtection);
        if (!UnwindStatus)
        {
            ERR_PRINT(
                "VirtualProtectEx failed: %u (lpAddress = %p, flNewProtect = 0x%X)\n",
                GetLastError(),
                pDbgBreakPoint,
                PreviousProtection);
        }
    }

    return status;
}
