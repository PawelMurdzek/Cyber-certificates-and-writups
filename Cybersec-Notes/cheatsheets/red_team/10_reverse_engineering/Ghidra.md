# Ghidra

NSA's open-source reverse engineering tool.

## Getting Started

### Installation
```bash
# Download from https://ghidra-sre.org/
# Extract and run
./ghidraRun  # Linux
ghidraRun.bat  # Windows
```

### Creating a Project
1. File → New Project
2. Select Non-Shared Project
3. Choose directory and project name

### Importing a Binary
1. File → Import File
2. Select binary (EXE, DLL, ELF, etc.)
3. Accept default analyzer options
4. Double-click file to open CodeBrowser

---

## Interface Overview

| Window | Purpose |
|:-------|:--------|
| **Listing** | Disassembly view |
| **Decompile** | C-like pseudocode |
| **Symbol Tree** | Functions, imports, exports |
| **Data Type Manager** | Data structures |
| **Function Graph** | Visual control flow |

---

## Essential Keyboard Shortcuts

| Shortcut | Action |
|:---------|:-------|
| `G` | Go to address |
| `L` | Rename (label) |
| `Ctrl+E` | Edit function signature |
| `T` | Set/Change data type |
| `;` | Add comment |
| `D` | Disassemble |
| `C` | Clear code |
| `P` | Create function |
| `Ctrl+Shift+E` | Export program |
| `Space` | Toggle Graph/Listing |

---

## Basic Workflow

### 1. Initial Analysis
- Let Ghidra's auto-analysis complete
- Check Analysis → Auto Analyze (if not done)

### 2. Finding Entry Points
- Look in **Symbol Tree** → Functions → `entry` or `main`
- Check **Exports** for interesting functions

### 3. String Search
- Search → For Strings
- Look for interesting strings (passwords, URLs, flags)
- Double-click to navigate

### 4. Function Analysis
- Rename functions (L key)
- Add comments (;)
- Edit signatures (Ctrl+E)

---

## Finding Important Functions

### Imports
Check Symbol Tree → Imports for:
- `CreateProcess`, `WinExec` - Execution
- `VirtualAlloc`, `VirtualProtect` - Memory manipulation
- `CreateFile`, `WriteFile` - File operations
- `RegSetValue` - Registry modification
- `socket`, `connect`, `send` - Network operations

### Strings to Search
- Error messages
- Registry keys
- URLs, IPs
- File paths
- Credentials

---

## Decompiler Tips

### Fixing Decompilation
```c
// If parameters look wrong
// Right-click function → Edit Function Signature
// Fix return type and parameters

// If variables are wrong types
// Right-click variable → Retype Variable
```

### Common Issues
| Problem | Solution |
|:--------|:---------|
| Wrong function signature | Edit Function Signature |
| Unrecognized struct | Create struct in Data Type Manager |
| Missing function | Create function at address (P) |
| Bad decompilation | Try re-analyzing or manual disassembly |

---

## Data Types

### Creating Structures
1. Window → Data Type Manager
2. Right-click → New → Structure
3. Add fields with correct types

### Applying Types
- Select data, press `T`, choose type
- Right-click in Decompile → Retype Variable

---

## Scripting

### Python Scripts
```python
# Example: Find all calls to a function
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import *

func = getFunction("InterestingFunction")
refs = getReferencesTo(func.getEntryPoint())
for ref in refs:
    print(ref.getFromAddress())
```

### Running Scripts
- Window → Script Manager
- Or: `analyzeHeadless` for batch processing

---

## Practical Tips

### Malware Analysis
1. Check strings for C2 addresses
2. Look for crypto functions (XOR loops, AES, etc.)
3. Find process injection (VirtualAllocEx, WriteProcessMemory)
4. Check persistence mechanisms

### CTF Challenges
1. Find `main()` or entry point
2. Search for "flag", "password", comparisons
3. Trace user input through program
4. Look for crypto/encoding functions

### Firmware Analysis
1. Identify architecture correctly
2. Set correct base address
3. Look for hardcoded credentials
4. Find command handlers

---

## Useful Plugins

| Plugin | Purpose |
|:-------|:--------|
| **FindCrypt** | Detect crypto constants |
| **Ghidra2IDA** | Export to IDA format |
| **BinExport** | Export for BinDiff |
| **GhidraBridge** | Python scripting |

---

## Comparison with Other Tools

| Tool | Pros | Cons |
|:-----|:-----|:-----|
| **Ghidra** | Free, great decompiler | Steeper learning curve |
| **IDA Pro** | Industry standard | Expensive |
| **Binary Ninja** | Modern UI | Paid |
| **radare2** | Free, scriptable | Command-line based |

---

## Resources

- [Ghidra Official](https://ghidra-sre.org/)
- [Ghidra Cheat Sheet](https://ghidra-sre.org/CheatSheet.html)
- [Ghidra Course](https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra)
