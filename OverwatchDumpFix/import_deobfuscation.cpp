#include "import_deobfuscation.h"

#include <malloc.h>

#include "ntdll.h"
#include "plugin.h"

#include "..\hde\hde.h"


//
// Define an arbitrary limit to the amount of IAT entries we parse before
//  assuming failure.
//
#define IAT_ENTRY_LIMIT 1500


//
// IdfpGetIatEntries
//
// Copy the import address table from the remote process into a local buffer.
//
// On success, callers must free 'ppIatEntries' via 'HeapFree'.
//
_Check_return_
BOOL
IdfpGetIatEntries(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ ULONG_PTR IatSection,
    _In_ ULONG cbIatSection,
    _Outptr_ PULONG_PTR* ppIatEntries,
    _Out_ PSIZE_T pcIatEntries
)
{
    PULONG_PTR pIatEntries = NULL;
    ULONG cbIatEntries = 0;
    ULONG cLastEntry = 0;
    SIZE_T cIatEntries = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *ppIatEntries = NULL;
    *pcIatEntries = 0;

    //
    // Lazily clamp our search range.
    //
    cbIatEntries = min(cbIatSection, IAT_ENTRY_LIMIT * sizeof(*pIatEntries));
    cLastEntry = cbIatEntries / sizeof(ULONG_PTR);

    pIatEntries = (PULONG_PTR)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        cbIatEntries);
    if (!pIatEntries)
    {
        ERR_PRINT("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Copy our IAT search range into a local buffer.
    //
    status = ReadProcessMemory(
        hProcess,
        (PVOID)IatSection,
        pIatEntries,
        cbIatEntries,
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "ReadProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            IatSection,
            cbIatEntries);
        goto exit;
    }

    for (ULONG_PTR i = 0; i < cLastEntry && pIatEntries[i] < ImageBase; ++i)
    {
        cIatEntries++;
    }

    // Set out parameters.
    *ppIatEntries = pIatEntries;
    *pcIatEntries = cIatEntries;

exit:
    if (!status)
    {
        if (pIatEntries)
        {
            if (!HeapFree(GetProcessHeap(), 0, pIatEntries))
            {
                ERR_PRINT("HeapFree failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}


//
// Instruction format values used in the deobfuscation code.
//
#define INSN_OPCODE_IMUL                    0x0F
#define INSN_OPCODE_MOV_R64_IMM64           0xB8
#define INSN_OPCODE_MOV_R64_IMM64_RAX_R10   0xBA
#define INSN_OPCODE_ADD_R64_IMM32           0x05
#define INSN_OPCODE_SUB_R64_IMM32           0x2D
#define INSN_OPCODE_XOR_R64_IMM32           0x35
#define INSN_OPCODE_JMP_REL32               0xE9
#define INSN_OPCODE_JMP_REG                 0xFF


//
// IdfpDeobfuscateEntry
//
_Check_return_
BOOL
IdfpDeobfuscateEntry(
    _In_ PVOID pEmulationBuffer,
    _In_ PVOID pDeobfuscationPage,
    _In_ ULONG_PTR EntryOffset,
    _Out_ PULONG_PTR pDeobfuscatedEntry
)
{
    HDE_DISASSEMBLY Disassembly = {};
    UINT cbInstruction = 0;
    ULONG_PTR IntermediateEntry = 0;
    BOOLEAN fIsBranchInstruction = FALSE;
    ULONG_PTR DeobfuscatedEntry = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDeobfuscatedEntry = NULL;

    // Storing r10 value during 0xBA (mov r10, imm64) operation
    ULONG64 r10 = 0;

    for (PVOID pInstruction = (PVOID)((ULONG_PTR)pEmulationBuffer + EntryOffset);
        pInstruction >= pEmulationBuffer &&
        pInstruction < (PVOID)((ULONG_PTR)pEmulationBuffer + PAGE_SIZE);
        /**/)
    {
        //
        // Reset instruction state parameters.
        //
        fIsBranchInstruction = FALSE;

        cbInstruction = HdeDisassemble(pInstruction, &Disassembly);
        if (!cbInstruction)
        {
            ERR_PRINT("HdeDisassemble failed for remote address: %p\n",
                (ULONG_PTR)pDeobfuscationPage +
                (ULONG_PTR)pInstruction -
                (ULONG_PTR)pEmulationBuffer);
            status = FALSE;
            goto exit;
        }
        //
        if (F_ERROR & Disassembly.flags)
        {
            ERR_PRINT("Encountered invalid instruction at %p\n",
                (ULONG_PTR)pDeobfuscationPage +
                (ULONG_PTR)pInstruction -
                (ULONG_PTR)pEmulationBuffer);
            status = FALSE;
            goto exit;
        }

        //
        // Emulate the instruction and apply all side effects to our
        //  intermediate entry value.
        //
        switch (Disassembly.opcode)
        {
        case INSN_OPCODE_MOV_R64_IMM64_RAX_R10:
            // Store r10 value from the operation (used later)
            r10 = Disassembly.imm.imm64;
            break;

        case INSN_OPCODE_MOV_R64_IMM64:
            IntermediateEntry = Disassembly.imm.imm64;
            break;

        case INSN_OPCODE_ADD_R64_IMM32:
            IntermediateEntry += Disassembly.imm.imm32;
            break;

        case INSN_OPCODE_SUB_R64_IMM32:
            IntermediateEntry -= Disassembly.imm.imm32;
            break;

        case INSN_OPCODE_XOR_R64_IMM32:
            IntermediateEntry ^= Disassembly.imm.imm32;
            break;

        case INSN_OPCODE_JMP_REL32:
            pInstruction = (PVOID)(
                (ULONG_PTR)pInstruction +
                cbInstruction +
                (LONG)Disassembly.imm.imm32);

            fIsBranchInstruction = TRUE;

            break;

        case INSN_OPCODE_JMP_REG:
            DeobfuscatedEntry = IntermediateEntry;
            break;

        case INSN_OPCODE_IMUL:
            // Handle our errors, just in case so we don't have to look forever later
            if (r10 == 0)
            {
                ERR_PRINT("r10 == 0, opcode: 0x%X\n", Disassembly.opcode);
                status = FALSE;
                goto exit;
            }
            // Multiply with r10 stored value
            IntermediateEntry *= r10;
            // reset r10 (dont know if this makes a difference but good practice I guess?)
            r10 = 0;
            break;

        default:
            ERR_PRINT("Unhandled opcode: 0x%X\n", Disassembly.opcode);
            status = FALSE;
            goto exit;
        }

        //
        // Emulate execution flow if this is not a branch instruction.
        //
        if (!fIsBranchInstruction)
        {
            pInstruction = (PVOID)((ULONG_PTR)pInstruction + cbInstruction);
        }

        //
        // Exit if deobfuscation is complete.
        //
        if (DeobfuscatedEntry)
        {
            break;
        }
    }
    //
    if (!DeobfuscatedEntry)
    {
        ERR_PRINT("Failed to deobfuscate entry.\n");
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pDeobfuscatedEntry = DeobfuscatedEntry;

exit:
    return status;
}


//
// We use two pages for the emulation buffer so that we do not have the handle
//  edge cases where the diassembler incorrectly reads past the page boundary.
//
#define EMULATION_BUFFER_SIZE   (PAGE_SIZE * 2)


//
// IdfpDeobfuscateIatEntries
//
// Deobfuscate the elements in 'pIatEntries'. Each obfuscated pointer is
//  overwritten with its deobfuscated import address in the remote process.
//
_Check_return_
BOOL
IdfpDeobfuscateIatEntries(
    _In_ HANDLE hProcess,
    _Inout_ PULONG_PTR pIatEntries,
    _In_ SIZE_T cIatEntries
)
{
    PVOID pEmulationBuffer = NULL;
    PVOID pDeobfuscationPage = NULL;
    ULONG_PTR EntryOffset = 0;
    ULONG_PTR DeobfuscatedEntry = 0;
    SIZE_T cDeobfuscatedEntries = 0;
    BOOL status = TRUE;

    //
    // Allocate a page aligned buffer to store the contents of the
    //  deobfuscation page in the remote process.
    //
    pEmulationBuffer = _aligned_malloc(EMULATION_BUFFER_SIZE, PAGE_SIZE);
    if (!pEmulationBuffer)
    {
        ERR_PRINT("_aligned_malloc failed: %d\n", errno);
        status = FALSE;
        goto exit;
    }

    //
    // Deobfuscate all IAT entries.
    //
    for (SIZE_T i = 0; i < cIatEntries; ++i)
    {
        //
        // Skip null entries.
        //
        if (!pIatEntries[i])
        {
            continue;
        }

        //
        // Reset the emulation buffer for each entry.
        //
        RtlSecureZeroMemory(pEmulationBuffer, EMULATION_BUFFER_SIZE);

        //
        // Calculate the address of the page containing the deobfuscation code
        //  for this entry.
        //
        pDeobfuscationPage = (PVOID)ALIGN_DOWN_BY(pIatEntries[i], PAGE_SIZE);

        //
        // TODO We should VirtualQuery the deobfuscation page to verify that it
        //  is valid and readable.
        //
        status = ReadProcessMemory(
            hProcess,
            pDeobfuscationPage,
            pEmulationBuffer,
            PAGE_SIZE,
            NULL);
        if (!status)
        {
            ERR_PRINT(
                "ReadProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
                GetLastError(),
                pDeobfuscationPage,
                PAGE_SIZE);
            goto exit;
        }

        EntryOffset = BYTE_OFFSET(pIatEntries[i]);

        status = IdfpDeobfuscateEntry(
            pEmulationBuffer,
            pDeobfuscationPage,
            EntryOffset,
            &DeobfuscatedEntry);
        if (!status)
        {
            ERR_PRINT("IdfpDeobfuscateEntry failed for entry: %p.\n",
                pIatEntries[i]);
            goto exit;
        }

        //
        // Update the entry.
        //
        pIatEntries[i] = DeobfuscatedEntry;

        cDeobfuscatedEntries++;
    }

    INF_PRINT("Successfully deobfuscated %Iu IAT entries.\n",
        cDeobfuscatedEntries);

exit:
    if (pEmulationBuffer)
    {
        _aligned_free(pEmulationBuffer);
    }

    return status;
}


//
// IdfpPatchImportAddressTable
//
_Check_return_
BOOL
IdfpPatchImportAddressTable(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ const REMOTE_PE_HEADER& RemotePeHeader,
    _In_ ULONG_PTR IatSection,
    _In_ PULONG_PTR pDeobfuscatedIatEntries,
    _In_ SIZE_T cIatEntries

)
{
    PIMAGE_DATA_DIRECTORY pImageDataDirectoryIat = NULL;
    IMAGE_DATA_DIRECTORY IatDataDirectoryPatch = {};
    SIZE_T cbIatEntries = 0;
    BOOL status = TRUE;

    INF_PRINT("Patching the import address table...\n");

    cbIatEntries = cIatEntries * sizeof(ULONG_PTR);

    //
    // Patch the IAT data directory entry in the remote pe header to reflect
    //  our deobfuscated IAT. We must do this so that Scylla can correctly
    //  rebuild the IAT.
    //
    // Calculate the address of the remote IAT data directory entry.
    //
    pImageDataDirectoryIat = (PIMAGE_DATA_DIRECTORY)(
        ImageBase +
        (ULONG_PTR)&RemotePeHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] -
        (ULONG_PTR)&RemotePeHeader.dosHeader);

    //
    // Sanity check.
    //
    if (cbIatEntries > MAXDWORD)
    {
        ERR_PRINT("Unexpected IAT entries size: 0x%IX\n", cbIatEntries);
        status = FALSE;
        goto exit;
    }

    //
    // Initialize the data directory patch.
    //
    IatDataDirectoryPatch.VirtualAddress = (DWORD)(IatSection - ImageBase);
    IatDataDirectoryPatch.Size = (DWORD)cbIatEntries;

    INF_PRINT("Patching the IAT data directory entry at %p:\n",
        pImageDataDirectoryIat);
    INF_PRINT("    VirtualAddress:  0x%X\n",
        IatDataDirectoryPatch.VirtualAddress);
    INF_PRINT("    Size:            0x%X\n", IatDataDirectoryPatch.Size);

    //
    // Write the patch to the remote process.
    //
    status = WriteProcessMemory(
        hProcess,
        pImageDataDirectoryIat,
        &IatDataDirectoryPatch,
        sizeof(IatDataDirectoryPatch),
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "WriteProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            pImageDataDirectoryIat,
            sizeof(IatDataDirectoryPatch));
        goto exit;
    }

    //
    // Overwrite the obfuscated IAT in the remote process with the deobfuscated
    //  table.
    //
    status = WriteProcessMemory(
        hProcess,
        (PVOID)IatSection,
        pDeobfuscatedIatEntries,
        cbIatEntries,
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "WriteProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            IatSection,
            cbIatEntries);
        goto exit;
    }

    INF_PRINT("Successfully patched remote IAT.\n");

exit:
    return status;
}


//
// IdfDeobfuscateImportAddressTable
//
_Use_decl_annotations_
BOOL
IdfDeobfuscateImportAddressTable(
    HANDLE hProcess,
    ULONG_PTR ImageBase,
    ULONG cbImageSize,
    const REMOTE_PE_HEADER& RemotePeHeader
)
{
    PIMAGE_SECTION_HEADER pIatSectionHeader = NULL;
    ULONG_PTR IatSection = 0;
    ULONG cbIatSection = 0;
    PULONG_PTR pIatEntries = NULL;
    SIZE_T cIatEntries = 0;
    BOOL status = TRUE;

    INF_PRINT("Deobfuscating the import address table...\n");

    pIatSectionHeader = GetPeSectionByName(RemotePeHeader, ".rdata");
    if (!pIatSectionHeader)
    {
        ERR_PRINT("Error: failed to get PE section containing the IAT.\n");
        status = FALSE;
        goto exit;
    }

    IatSection = ImageBase + pIatSectionHeader->VirtualAddress;
    cbIatSection = pIatSectionHeader->Misc.VirtualSize;

    //
    // Verify that the IAT section is inside the target image.
    //
    if (IatSection < ImageBase ||
        ImageBase + cbImageSize < IatSection + cbIatSection)
    {
        ERR_PRINT("Error: IAT section is corrupt.\n");
        ERR_PRINT("    IatSection:      %p - %p\n",
            IatSection,
            IatSection + cbIatSection);
        ERR_PRINT("    Debuggee Image:  %p - %p\n",
            ImageBase,
            ImageBase + cbImageSize);
        status = FALSE;
        goto exit;
    }

    INF_PRINT("Found the remote IAT: %p\n", IatSection);

    status = IdfpGetIatEntries(
        hProcess,
        ImageBase,
        IatSection,
        cbIatSection,
        &pIatEntries,
        &cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to enumerate IAT entries.\n");
        goto exit;
    }

    INF_PRINT("The remote IAT contains %Iu elements.\n", cIatEntries);

    status = IdfpDeobfuscateIatEntries(
        hProcess,
        pIatEntries,
        cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to deobfuscate the remote IAT.\n");
        goto exit;
    }

    status = IdfpPatchImportAddressTable(
        hProcess,
        ImageBase,
        RemotePeHeader,
        IatSection,
        pIatEntries,
        cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to patch the remote IAT.\n");
        goto exit;
    }

    INF_PRINT("Successfully restored the remote IAT.\n");

exit:
    if (pIatEntries)
    {
        if (!HeapFree(GetProcessHeap(), 0, pIatEntries))
        {
            ERR_PRINT("HeapFree failed: %u\n", GetLastError());
        }
    }

    return status;
}
