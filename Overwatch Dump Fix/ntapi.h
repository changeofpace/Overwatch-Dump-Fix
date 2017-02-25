#pragma once

#include <Windows.h>

namespace ntapi {

typedef long NTSTATUS;

////////////////////////////////////////////////////////////////////////////////
// Rewritten Macros

__forceinline NTSTATUS NT_SUCCESS(NTSTATUS Status) { return Status >= 0; }

////////////////////////////////////////////////////////////////////////////////
// Section Access Rights

const ULONG SEC_NO_CHANGE = 0x00400000;

////////////////////////////////////////////////////////////////////////////////
// Status Codes

const NTSTATUS STATUS_SUCCESS =                 0x00000000;
const NTSTATUS STATUS_ACCESS_DENIED =           0xC0000022;
const NTSTATUS STATUS_INVALID_PAGE_PROTECTION = 0xC0000045;
const NTSTATUS STATUS_SECTION_PROTECTION =      0xC000004E;
const NTSTATUS STATUS_PROCEDURE_NOT_FOUND =     0xC000007A;

////////////////////////////////////////////////////////////////////////////////
// Types

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

////////////////////////////////////////////////////////////////////////////////
// Section Objects

NTSTATUS
NTAPI
NtCreateSection(
    _Out_    PHANDLE            SectionHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes,
    _In_opt_ HANDLE             FileHandle
);

NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           Win32Protect
);

NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_     HANDLE ProcessHandle,
    _In_opt_ PVOID  BaseAddress
);

////////////////////////////////////////////////////////////////////////////////
// Virtual Memory

NTSTATUS
NTAPI
NtProtectVirtualMemory(
    IN      HANDLE      ProcessHandle,
    IN OUT  PVOID       *BaseAddress,
    IN OUT  PSIZE_T     NumberOfBytesToProtect,
    IN      ULONG       NewAccessProtection,
    OUT     PULONG      OldAccessProtection
);

NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_      HANDLE                   ProcessHandle,
    _In_opt_  PVOID                    BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID                    MemoryInformation,
    _In_      SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T                  ReturnLength
);

NTSTATUS
NTAPI
NtReadVirtualMemory(
    IN  HANDLE          ProcessHandle,
    IN  PVOID           BaseAddress,
    OUT PVOID           Buffer,
    IN  SIZE_T          NumberOfBytesToRead,
    OUT PSIZE_T         NumberOfBytesReaded OPTIONAL
);

NTSTATUS
NTAPI
NtWriteVirtualMemory(
    IN  HANDLE          ProcessHandle,
    IN  PVOID           BaseAddress,
    IN  PVOID           Buffer,
    IN  SIZE_T          NumberOfBytesToWrite,
    OUT PSIZE_T         NumberOfBytesWritten OPTIONAL
);

} // namespace ntapi