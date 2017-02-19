# Overwatch Dump Fix

## Summary

This plugin removes anti-dumping and obfuscation techniques from the popular FPS game Overwatch.  This project is a continuous effort to reverse engineer Overwatch's protection as it is modified and improved in future patches.

## Added commands

- **OverwatchDumpFix**

## Usage

### x64dbg

1. Attach x64dbg to Overwatch.exe then execute the **OverwatchDumpFix** command.
2. Open Scylla, select Overwatch.exe in the "attach process" drop-down list.
3. Click "IAT Autosearch".
4. Click "Get Imports".
5. Click "Dump" and save the file as an .exe.
6. Click "Fix Dump" and select the dump file (adjust the type filter).
7. The Scylla ouput view should say "Import Rebuild success [FILE PATH]".
8. Click "PE Rebuild" and select the fixed dump file.

### IDA Pro

9. Open the dump file in IDA.  Check the "Manual Load" box.  Click "OK" / "Yes" for every prompt.
10. Run the "Universal Unpacker Manual Reconstruct" plugin for the IAT to set imports to the correct color.
11. Happy reversing :sunglasses:.

## Building

A post-build event requires the **"X64DBG_PATH"** environment variable to be defined to x64dbg's installation directory.

## Notes

- This plugin is tested while offline on battlenet.