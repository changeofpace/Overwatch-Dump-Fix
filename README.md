# Overwatch Dump Fix

## Summary

This x64dbg plugin removes anti-dumping and obfuscation techniques from the popular FPS game Overwatch. It is meant to be used with Scylla (built into x64dbg) to produce dump files for static analysis.

This project is a continuous effort to reverse engineer Overwatch's protection as it is modified and improved in future patches.

## Release v3.0 (3.8.2017)

- Updated for new protection tech in Overwatch version 1.8.0.2.34978.
- Import thunks are now spread across several memory regions. Each thunk has multiple blocks combined with relative jumps.
- Now using capstone disassembler to unpack import thunks.
- The .rdata view contains 0x1000 bytes of code (not sure if this is new). The plugin will separate this page from .rdata. IDA will automatically combine the two .text sections.

## Usage

### Added commands

- **OverwatchDumpFix** [verbose]

### Syntax

Invoking the command with an argument that evaluates to true, e.g. 1, will enable verbose output.

### x64dbg

1. Attach x64dbg to Overwatch.exe then execute the **OverwatchDumpFix** command.
2. Open **Scylla** in x64dbg's **Plugins** menu then select Overwatch.exe in the "Attach to an active process" drop-down list.
3. Click **IAT Autosearch** -> **Get Imports**.
4. Click **Dump** to create a dump file.
5. Click **Fix Dump** and select the dump file from (4) to reconstruct imports.
6. The Scylla output view should say "Import Rebuild success [FILE PATH]".
7. Click **PE Rebuild** and select the fixed dump file.

### IDA Pro

8. Open the dump file in IDA. Check the **Manual load** and **Load resources** (optional) boxes.  Click **OK** / **Yes** for every prompt.
9. Run the **Universal Unpacker Manual Reconstruct** plugin for the IAT to set imports to the correct color.
10. Happy reversing :sunglasses:.

## Building

A post-build event requires the **"X96DBG_PATH"** environment variable to be defined to x64dbg's installation directory.

## Notes

- This plugin is tested while offline on battlenet.
