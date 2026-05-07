def compute_serial_number_sum(s):
    return sum(int(c) for c in s)

def shift_serial(s):
    d = [int(c) for c in s]
    parts = [
        s[0],
        str(d[0] >> d[1]),
        s[2],
        str(d[2] >> d[3]),
        s[4],
        str(d[4] >> d[5]),
        s[6],
        str(d[6] >> d[7]),
    ]
    return ''.join(parts)

def compute_serial(shifted):
    return 905 ^ compute_serial_number_sum(shifted)

def compute_name(name):
    XOR = 10
    xored = bytes((b ^ XOR) & 0xff for b in name.encode('ascii'))
    return sum(xored)

def is_valid(text2, name="LABORATORIUM"):
    if len(text2) != 8 or not text2.isdigit():
        return False
    if compute_serial_number_sum(text2) != 36:
        return False
    shifted = shift_serial(text2)
    if len(shifted) != 8:
        return False
    n = int(shifted)
    if n // 1867 != 53480:
        return False
    if compute_name(name) != compute_serial(shifted):
        return False
    return True

name_val = compute_name("LABORATORIUM")
print(f"ComputeName('LABORATORIUM') = {name_val}")
print(f"905 XOR sum_of_shifted_digits must equal {name_val}")
print(f"  => sum_of_shifted_digits = {905 ^ name_val}")
print()

valid = []
for n in range(10**7, 10**8):
    s = f"{n:08d}"
    if is_valid(s):
        valid.append(s)

print(f"Found {len(valid)} valid serials:")
for s in valid:
    sh = shift_serial(s)
    print(f"  {s} -> shifted={sh} (int={int(sh)}, /1867={int(sh)//1867}, sum_digits={compute_serial_number_sum(sh)})")
