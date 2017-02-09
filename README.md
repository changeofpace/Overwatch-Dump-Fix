# Overwatch Dump Fix

## Summary

This plugin removes anti-dumping and obfuscation techniques from the popular FPS game Overwatch.  This project is a continuous effort to reverse engineer Overwatch's protection as it is modified and improved in future patches.

## Added commands

- **OverwatchDumpFix**

## Usage

### x64dbg

1. Attach x64dbg to Overwatch.exe then execute the **OverwatchDumpFix** command.
2. Save the output in the log tab:
    <pre>
    [Overwatch Dump Fix] dump fix complete.
    [Overwatch Dump Fix] Scylla IAT Info:
    [Overwatch Dump Fix]     OEP =  000000002DE70354
    [Overwatch Dump Fix]     VA =   000000002DF20000
    [Overwatch Dump Fix]     Size =             1140
    [Overwatch Dump Fix] IDA Pro Info:
    [Overwatch Dump Fix]     overwatch base address = 000000013F780000
    </pre>
3. Open Scylla, set Overwatch.exe as the attach process, click "Pick DLL".
4. Select Overwatch.exe in the module list (sort by ImageBase, it will be the lowest address).
5. Set the "OEP", "VA", and "Size" values according to log output.
6. Click "Get Imports".
7. Click "Dump" and save the file as an .exe.
8. Click "Fix Dump" and select the dump file (adjust the type filter).
9. The Scylla ouput view should say "Import Rebuild success [FILE PATH]".
10. Click "PE Rebuild" and select the fixed dump file.

### IDA Pro

11. Open the dump file in IDA.  Check the "Manual Load" box.  Click "OK" / "Yes" for every prompt.
12. Wait for IDA to finish analysis.
13. Execute the **correct_invalid_RVAs.py** script using the overwatch base address from log output.
14. Happy reversing :sunglasses:.

## Building

A post-build event requires the **"X64DBG_PATH"** environment variable to be defined to x64dbg's installation directory.

## Notes

- This plugin is tested while offline on battlenet.