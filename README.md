# Overwatch Dump Fix

## added commands

- **OverwatchDumpFix**

## usage

1. attach x64dbg to overwatch.exe.
2. exec **OverwatchDumpFix**.
3. open Scylla then select overwatch.exe (reselect it or ntdll.dll is used).
4. click "IAT Autosearch".
5. click "Get Imports".
6. dump the file.
7. click "Fix Dump", then select the dumped file to rebuild imports.

## features

* restores PE Header
* removes .text section segmentation
* adjusts iat to allow Scylla to rebuild imports
* patches "garbage" code with 0xCC
