# RiftByte

A binary diff tool for PE (EXE/DLL) and ELF files.  
Compares two binaries byte-by-byte, resolves virtual addresses, identifies sections, decodes x86/x64/ARM instructions, and exports results as a log file and an x64dbg-compatible `.1337` patch file.

---

## Features

- Supports **PE** (x32/x64 EXE & DLL) and **ELF** (32/64-bit) formats
- Detects architecture: **x86**, **x64**, **ARM32**, **ARM64**
- Resolves **Virtual Address (VA)** and **file offset** for every difference
- Identifies the **PE/ELF section** each change belongs to
- Decodes changed bytes as **x86/x64 or ARM mnemonics**
- Prints **jump/call targets** for branch instructions
- Shows surrounding byte context for each diff
- Exports a **`.log`** file with full diff summary
- Exports a **`.1337`** patch file compatible with **x64dbg / x32dbg / arm64dbg**
- Colored terminal output (ANSI, works in Windows Console)
- Detects `.NET` assemblies

---

## Usage

```
RiftByte <original_file> <modified_file>
```

**Example:**
```
RiftByte original.exe patched.exe
```

Output files are created automatically next to the input file:
- `original.exe.log` — human-readable diff log
- `original.exe.1337` — x64dbg patch file

---

## Building

> Requires **WSL (Ubuntu)**, **GCC**, and **TCC** installed.

**Without icon:**
```bat
build.bat
```

**With icon:**
```bat
build_Icon.bat
```

### Prerequisites

Install inside Ubuntu WSL:
```bash
sudo apt update
sudo apt install gcc tcc
```

---

## Output Example

```
[ x64 | EXE ]  ImageBase: 0000000140000000  EntryPoint: 0000000140001000  (original)
[ .text ]  [ x64dbg ]  0000000140005A10   OFF:0x00001A10 | MOV EAX, imm  ->  XOR EAX, EAX  (B8 01 00 00 00 -> 33 C0)
  full bytes: ... B8 01 00 00 00 ...
           -> ... 33 C0 ...
```

---

## License

MIT
