# Overwatch Dump Fix

## Summary

This x64dbg plugin removes anti-dumping and obfuscation techniques from the popular FPS game Overwatch. It is meant to be used with Scylla (built into x64dbg) to produce process dump files for static analysis.

This project is for educational use only.

## Release v5.1.0 (2019.03.16)

- Replaced capstone disassembler with hde.
- Updated instructions to reflect requirement of the Scylla 'Use advanced IAT search' setting.

## Release v5.0.2 (2018.06.17)

- Removed post-build event.
- Removed process name check in 'CBCREATEPROCESS' to allow the plugin to be executed for other games.

## Release v5.0.1 (2017.05.23)

- Updated for Overwatch version 1.11.1.2.36859.
- The import address table is no longer terminated by two null pointers. The second null has been replaced with a pointer to a 'ret 0' instruction.

## Usage

### Added commands

- **OverwatchDumpFix**

### x64dbg

1. Attach x64dbg to Overwatch.exe then execute the **OverwatchDumpFix** command.
2. Open **Scylla** in x64dbg's **Plugins** menu then select Overwatch.exe in the "Attach to an active process" drop-down list.
3. Click **IAT Autosearch**.
4. A dialog box will inform the user that the IAT search advanced result does not match the normal search result. Click **Yes**.
5. Verify that the address of the **VA* field in the **IAT Info** region matches the address of the IAT found in the log tab.
6. Click **Get Imports**.
7. Click **Dump** to create a dump file.
8. Click **Fix Dump** and select the dump file from (7) to reconstruct imports.
9. The Scylla output view should say "Import Rebuild success [FILE PATH]".
10. Click **PE Rebuild** and select the fixed dump file.

### IDA Pro

8. Open the dump file in IDA. Check the **Manual load** and **Load resources** (optional) boxes.  Click **OK** / **Yes** for every prompt.
9. Run the **Universal Unpacker Manual Reconstruct** plugin for the IAT to set imports to the correct color.
10. Happy reversing :sunglasses:.

## Notes

- This plugin is tested while offline on battlenet.
