# Overwatch Dump Fix

## Summary

This x64dbg plugin removes anti-dumping and obfuscation techniques from the popular FPS game Overwatch. It is meant to be used with Scylla (built into x64dbg) to produce process dump files for static analysis.

This project is a continuous effort to reverse engineer Overwatch's protection as it is modified and improved in future patches.

## Release v4.0.0 (4.18.2017)

- Updated for new protection tech in Overwatch version 1.10.0.2.36031.
- The 'secret' pe header is no longer stored in memory (or it's now obfuscated). The plugin now uses the pe header from the file on disk as a base when patching Overwatch's invalid pe header.

## Usage

### Added commands

- **OverwatchDumpFix**

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
