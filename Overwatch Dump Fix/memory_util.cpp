#include "memory_util.h"
#include "plugin.h"

bool memutil::RemoteWrite(ULONG_PTR BaseAddress, const PVOID SourceAddress, SIZE_T WriteSize)
{
    SIZE_T nbytes = 0;
    BOOL status = WriteProcessMemory(debuggee::hProcess, PVOID(BaseAddress), SourceAddress, WriteSize, &nbytes);
    return status && nbytes == WriteSize;
}

bool memutil::RemoteRead(ULONG_PTR BaseAddress, const PVOID DestinationAddress, SIZE_T ReadSize)
{
    SIZE_T nbytes = 0;
    BOOL status = ReadProcessMemory(debuggee::hProcess, PVOID(BaseAddress), DestinationAddress, ReadSize, &nbytes);
    return status && nbytes == ReadSize;
}