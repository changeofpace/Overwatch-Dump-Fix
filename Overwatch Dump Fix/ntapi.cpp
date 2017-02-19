#include "ntapi.h"

static HMODULE hmNtdll = GetModuleHandleA("ntdll.dll");

////////////////////////////////////////////////////////////////////////////////
// Section Objects

ntapi::NTSTATUS
NTAPI
ntapi::NtCreateSection(
    _Out_    PHANDLE            SectionHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes,
    _In_opt_ HANDLE             FileHandle)
{
    typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static NtCreateSection_t Fn = NtCreateSection_t(GetProcAddress(hmNtdll, "NtCreateSection"));
    if (Fn)
        return Fn(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}

ntapi::NTSTATUS
NTAPI
ntapi::NtMapViewOfSection(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           Win32Protect)
{
    typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
    static NtMapViewOfSection_t Fn = NtMapViewOfSection_t(GetProcAddress(hmNtdll, "NtMapViewOfSection"));
    if (Fn)
        return Fn(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}

ntapi::NTSTATUS
NTAPI
ntapi::NtUnmapViewOfSection(
    _In_     HANDLE ProcessHandle,
    _In_opt_ PVOID  BaseAddress)
{
    typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
    static NtUnmapViewOfSection_t Fn = NtUnmapViewOfSection_t(GetProcAddress(hmNtdll, "NtUnmapViewOfSection"));
    if (Fn)
        return Fn(ProcessHandle, BaseAddress);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}

////////////////////////////////////////////////////////////////////////////////
// Virtual Memory

ntapi::NTSTATUS
NTAPI
ntapi::NtProtectVirtualMemory(
    IN      HANDLE      ProcessHandle,
    IN OUT  PVOID       *BaseAddress,
    IN OUT  PSIZE_T     NumberOfBytesToProtect,
    IN      ULONG       NewAccessProtection,
    OUT     PULONG      OldAccessProtection)
{
    typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID, PSIZE_T, ULONG, PULONG);
    static NtProtectVirtualMemory_t Fn = NtProtectVirtualMemory_t(GetProcAddress(hmNtdll, "NtProtectVirtualMemory"));
    if (Fn)
        return Fn(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}

ntapi::NTSTATUS
NTAPI
ntapi::NtQueryVirtualMemory(
    _In_      HANDLE                   ProcessHandle,
    _In_opt_  PVOID                    BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID                    MemoryInformation,
    _In_      SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T                  ReturnLength)
{
    typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
    static NtQueryVirtualMemory_t Fn = NtQueryVirtualMemory_t(GetProcAddress(hmNtdll, "NtQueryVirtualMemory"));
    if (Fn)
        return Fn(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}

ntapi::NTSTATUS
NTAPI
ntapi::NtReadVirtualMemory(
    IN  HANDLE          ProcessHandle,
    IN  PVOID           BaseAddress,
    OUT PVOID           Buffer,
    IN  SIZE_T          NumberOfBytesToRead,
    OUT PSIZE_T         NumberOfBytesRead OPTIONAL)
{
    typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    static NtReadVirtualMemory_t Fn = NtReadVirtualMemory_t(GetProcAddress(hmNtdll, "NtReadVirtualMemory"));
    if (Fn)
        return Fn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}

ntapi::NTSTATUS
NTAPI
ntapi::NtWriteVirtualMemory(
    IN  HANDLE          ProcessHandle,
    IN  PVOID           BaseAddress,
    IN  PVOID           Buffer,
    IN  SIZE_T          NumberOfBytesToWrite,
    OUT PSIZE_T         NumberOfBytesWritten OPTIONAL)
{
    typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    static NtWriteVirtualMemory_t Fn = NtWriteVirtualMemory_t(GetProcAddress(hmNtdll, "NtWriteVirtualMemory"));
    if (Fn)
        return Fn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    SetLastError(ERROR_PROC_NOT_FOUND);
    return STATUS_PROCEDURE_NOT_FOUND;
}
