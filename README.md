## Overview

WinGadgetHunter is a simple pattern matching tool I use to search for ROP (Return-Oriented Programming) gadgets within Windows DLL files. 

## Features

- Searches for user-defined byte patterns within DLL files.
- Supports wildcards for more flexible pattern matching.
- Can scan all DLLs in a specified directory or a single DLL.
- Color-coded console output for easy interpretation.

## Dependencies

The program is written in C++ and makes use of the following libraries:

    <Windows.h>: Windows API for loading DLLs and obtaining code sections.
    <filesystem>: For file and directory operations.
    <iostream>, <iomanip>, <sstream>, <string>: For input-output operations and string manipulation.

## Building

This project targets MSVC C++17.

## Usage

Run the executable from the command line:

```
WinGadgetHunter <pattern> [-i <path>]

    <pattern>: The byte pattern to search for, given as space-separated hex bytes. Use * for a wildcard byte.

    [-i <path>] (Optional): Path of the directory containing DLLs or the path of a specific DLL file.
```

## Example

To search for the byte pattern `0f 05 * * 2e` in all DLL files in the directory C:\Windows\System32:

```
WinGadgetHunter.exe 0f 05 * * 2e"
```

To search for the same pattern but only in a specific DLL:

```
WinGadgetHunter.exe "0f 05 * * 2e"  -i "C:\Windows\System32\example.dll
```

## Output

The tool will print out each match, showing the DLL name, the offset of the match, and a sequence of bytes where the match was found. Bytes that match the pattern are highlighted.

## Contributing

Just use Yara instead
