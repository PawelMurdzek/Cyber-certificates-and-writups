"""
CTF Flag Solver for 'cf madness' challenge.

Binary: Linux ELF64, self-modifying / trampoline-based control flow obfuscation.

## Architecture discovered via static analysis:

The binary's main function falls into a massive NOP sled (64KB+) containing
72 stub islands (each computing r11 = 0x16d15 with no side effects) spaced
exactly 1052 bytes apart. The actual logic lives at 0x415e31.

### Execution mechanism (trampoline recursion):
- 0x415e31 is called once, processes one flag character, then modifies its
  own return address on the stack and executes 'ret', landing in a NOP sled
  position that runs forward through stubs/NOPs until reaching 0x415e31 again.
- 0x41b490 (80-bit x87 float) decreases by 726 each iteration, encoding the
  return address: ret = 0x415f9c - current_float_value
- After strlen=51 iterations, the 52nd call to 0x415e31 detects all flag chars
  have been processed and calls the check function.

### computed_array layout (0x41a480):
Each call to 0x415e31 writes 2 entries to computed_array:
  - Even entries [2*i]: FPU result = (-559038737 + 726*(strlen+1-i)) & 0xffffffff
    (flag-independent; depends only on flag length)
  - Odd entries [2*i+1]: fps[flag[i]] result
    = ((0xdeadbeef XOR flag[i]) XOR (i * 0x1337) XOR (counter * 0xabcd)) & 0xffffffff

### Counter for fps[flag[i]]:
  - i=0: counter = 1337 (initial value at 0x419040 in .data)
  - i>0: counter = i-1 (saved val from start of previous call to 0x415e31)

### Flag length derivation:
102 non-zero reference entries / 2 entries per call = 51 flag chars.

### Reference array (0x419460 in .data):
127 x 4-byte entries, first 102 non-zero.
"""

import struct

with open('chall', 'rb') as f:
    data = f.read()

# Read reference array (127 x 4-byte values at file offset 0x18460)
ref_file_offset = 0x18020 + (0x419460 - 0x419020)
refs = []
for i in range(127):
    refs.append(struct.unpack_from('<I', data, ref_file_offset + i*4)[0])

strlen = 51  # deduced: 102 non-zero ref entries / 2 per call = 51

print(f"Flag length: {strlen}")

# Verify even-indexed entries (FPU results, flag-independent)
print("Verifying even-indexed FPU results (flag-length check)...")
fpu_ok = True
for i in range(strlen):
    fpu_val = (-559038737 + 726 * (strlen + 1 - i)) & 0xffffffff
    if fpu_val != refs[2*i]:
        print(f"  MISMATCH at i={i}: FPU=0x{fpu_val:08x}, ref[{2*i}]=0x{refs[2*i]:08x}")
        fpu_ok = False
if fpu_ok:
    print(f"  All {strlen} even entries match! Flag length confirmed.")

# Solve each flag character from the odd-indexed reference entries
print("\nSolving flag characters...")
flag = []
for i in range(strlen):
    counter = 1337 if i == 0 else (i - 1)
    val = i
    target = refs[2*i + 1]

    found = None
    for c in range(0, 256):
        result = ((0xdeadbeef ^ c) ^ (val * 0x1337) ^ (counter * 0xabcd)) & 0xffffffff
        if result == target:
            found = c
            break

    if found is None:
        print(f"  No solution for position {i} (ref[{2*i+1}]=0x{target:08x})")
        flag.append('?')
    else:
        ch = chr(found) if 32 <= found <= 126 else '?'
        flag.append(ch)

flag_str = ''.join(flag)

# Full verification
print("\nFull verification...")
all_ok = True
for i in range(strlen):
    c = ord(flag_str[i])
    counter = 1337 if i == 0 else (i - 1)
    val = i

    result_fpu = (-559038737 + 726 * (strlen + 1 - i)) & 0xffffffff
    result_fps = ((0xdeadbeef ^ c) ^ (val * 0x1337) ^ (counter * 0xabcd)) & 0xffffffff

    if result_fpu != refs[2*i]:
        print(f"  FPU mismatch at i={i}")
        all_ok = False
    if result_fps != refs[2*i + 1]:
        print(f"  fps mismatch at i={i}: got 0x{result_fps:08x}, expected 0x{refs[2*i+1]:08x}")
        all_ok = False

if all_ok:
    print(f"  All {strlen*2} computed_array entries verified correctly!")

print(f"\nFLAG: {flag_str}")
