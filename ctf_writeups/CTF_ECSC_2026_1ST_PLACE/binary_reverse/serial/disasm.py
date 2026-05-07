import dnfile
import struct

pe = dnfile.dnPE(r'C:\projekty\cyber.mil\binary_reverse\serial\CrackMe.exe')
pe.parse_data_directories()
mdt = pe.net.mdtables
us_heap = pe.net.user_strings

OPCODES = {
    0x00: ('nop', 0), 0x01: ('break', 0),
    0x02: ('ldarg.0', 0), 0x03: ('ldarg.1', 0), 0x04: ('ldarg.2', 0), 0x05: ('ldarg.3', 0),
    0x06: ('ldloc.0', 0), 0x07: ('ldloc.1', 0), 0x08: ('ldloc.2', 0), 0x09: ('ldloc.3', 0),
    0x0a: ('stloc.0', 0), 0x0b: ('stloc.1', 0), 0x0c: ('stloc.2', 0), 0x0d: ('stloc.3', 0),
    0x0e: ('ldarg.s', 1), 0x0f: ('ldarga.s', 1), 0x10: ('starg.s', 1),
    0x11: ('ldloc.s', 1), 0x12: ('ldloca.s', 1), 0x13: ('stloc.s', 1),
    0x14: ('ldnull', 0), 0x15: ('ldc.i4.m1', 0),
    0x16: ('ldc.i4.0', 0), 0x17: ('ldc.i4.1', 0), 0x18: ('ldc.i4.2', 0), 0x19: ('ldc.i4.3', 0),
    0x1a: ('ldc.i4.4', 0), 0x1b: ('ldc.i4.5', 0), 0x1c: ('ldc.i4.6', 0), 0x1d: ('ldc.i4.7', 0),
    0x1e: ('ldc.i4.8', 0), 0x1f: ('ldc.i4.s', 1), 0x20: ('ldc.i4', 4),
    0x21: ('ldc.i8', 8), 0x22: ('ldc.r4', 4), 0x23: ('ldc.r8', 8),
    0x25: ('dup', 0), 0x26: ('pop', 0),
    0x28: ('call', 4), 0x29: ('calli', 4), 0x2a: ('ret', 0),
    0x2b: ('br.s', 1), 0x2c: ('brfalse.s', 1), 0x2d: ('brtrue.s', 1),
    0x2e: ('beq.s', 1), 0x2f: ('bge.s', 1), 0x30: ('bgt.s', 1),
    0x31: ('ble.s', 1), 0x32: ('blt.s', 1), 0x33: ('bne.un.s', 1),
    0x34: ('bge.un.s', 1), 0x35: ('bgt.un.s', 1), 0x36: ('ble.un.s', 1),
    0x37: ('blt.un.s', 1),
    0x38: ('br', 4), 0x39: ('brfalse', 4), 0x3a: ('brtrue', 4),
    0x3b: ('beq', 4), 0x3c: ('bge', 4), 0x3d: ('bgt', 4),
    0x3e: ('ble', 4), 0x3f: ('blt', 4), 0x40: ('bne.un', 4),
    0x41: ('bge.un', 4), 0x42: ('bgt.un', 4), 0x43: ('ble.un', 4),
    0x44: ('blt.un', 4), 0x45: ('switch', None),
    0x58: ('add', 0), 0x59: ('sub', 0), 0x5a: ('mul', 0),
    0x5b: ('div', 0), 0x5c: ('div.un', 0), 0x5d: ('rem', 0),
    0x5e: ('rem.un', 0), 0x5f: ('and', 0), 0x60: ('or', 0),
    0x61: ('xor', 0), 0x62: ('shl', 0), 0x63: ('shr', 0), 0x64: ('shr.un', 0),
    0x65: ('neg', 0), 0x66: ('not', 0),
    0x67: ('conv.i1', 0), 0x68: ('conv.i2', 0), 0x69: ('conv.i4', 0),
    0x6a: ('conv.i8', 0),
    0x6f: ('callvirt', 4), 0x70: ('cpobj', 4), 0x71: ('ldobj', 4),
    0x72: ('ldstr', 4), 0x73: ('newobj', 4),
    0x74: ('castclass', 4), 0x75: ('isinst', 4),
    0x7b: ('ldfld', 4), 0x7c: ('ldflda', 4),
    0x7d: ('stfld', 4), 0x7e: ('ldsfld', 4),
    0x7f: ('ldsflda', 4), 0x80: ('stsfld', 4), 0x81: ('stobj', 4),
    0x8c: ('box', 4), 0x8d: ('newarr', 4), 0x8e: ('ldlen', 0),
    0x8f: ('ldelema', 4),
    0x90: ('ldelem.i1', 0), 0x91: ('ldelem.u1', 0),
    0x92: ('ldelem.i2', 0), 0x93: ('ldelem.u2', 0),
    0x94: ('ldelem.i4', 0), 0x95: ('ldelem.u4', 0),
    0x9c: ('stelem.i1', 0), 0x9d: ('stelem.i2', 0),
    0x9e: ('stelem.i4', 0), 0xa0: ('stelem.r4', 0),
    0xa1: ('stelem.r8', 0), 0xa2: ('stelem.ref', 0),
    0xa3: ('ldelem', 4), 0xa4: ('stelem', 4), 0xa5: ('unbox.any', 4),
    0xd0: ('ldtoken', 4),
}

TOKEN_OPS = {'call','callvirt','newobj','ldstr','ldfld','stfld','ldsfld','stsfld','ldtoken','newarr','box','isinst','castclass','initobj','ldftn','ldvirtftn','stelem','ldelem','ldelema','unbox.any'}
SHORT_BRANCH = {'br.s','brfalse.s','brtrue.s','beq.s','bge.s','bgt.s','ble.s','blt.s','bne.un.s','bge.un.s','bgt.un.s','ble.un.s','blt.un.s'}
LONG_BRANCH = {'br','brfalse','brtrue','beq','bge','bgt','ble','blt','bne.un','bge.un','bgt.un','ble.un','blt.un'}

def resolve_token(tok):
    table = (tok >> 24) & 0xff
    rid = tok & 0xffffff
    if table == 0x06:
        try:
            return f"MethodDef::{mdt.MethodDef.rows[rid-1].Name}"
        except: return f"MethodDef[{rid}]"
    elif table == 0x0a:
        try:
            mr = mdt.MemberRef.rows[rid-1]
            cls = ""
            try:
                cls = str(mr.Class.row.TypeName) if mr.Class.row else ""
            except: pass
            return f"{cls}::{mr.Name}"
        except: return f"MemberRef[{rid}]"
    elif table == 0x70:
        try:
            return f"\"{us_heap.get(rid).value}\""
        except: return f"UserString[0x{rid:x}]"
    elif table == 0x04:
        try:
            return f"Field::{mdt.Field.rows[rid-1].Name}"
        except: return f"Field[{rid}]"
    elif table == 0x01:
        try:
            return f"TypeRef::{mdt.TypeRef.rows[rid-1].TypeName}"
        except: return f"TypeRef[{rid}]"
    elif table == 0x02:
        try:
            return f"TypeDef::{mdt.TypeDef.rows[rid-1].TypeName}"
        except: return f"TypeDef[{rid}]"
    return f"Token[0x{tok:x}]"

def disasm(code):
    i = 0
    out = []
    while i < len(code):
        op = code[i]
        offset = i
        if op == 0xfe:
            i += 1
            op2 = code[i]
            two_byte = {
                0x01: ('ceq', 0), 0x02: ('cgt', 0), 0x03: ('cgt.un', 0),
                0x04: ('clt', 0), 0x05: ('clt.un', 0),
                0x06: ('ldftn', 4), 0x07: ('ldvirtftn', 4),
                0x09: ('ldarg', 2), 0x0a: ('ldarga', 2), 0x0b: ('starg', 2),
                0x0c: ('ldloc', 2), 0x0d: ('ldloca', 2), 0x0e: ('stloc', 2),
                0x16: ('initobj', 4),
            }
            mnem, arg_size = two_byte.get(op2, (f'fe{op2:02x}', 0))
            i += 1
            if arg_size == 0:
                out.append((offset, mnem, None, ""))
            else:
                arg_bytes = code[i:i+arg_size]
                i += arg_size
                if arg_size == 4:
                    val = struct.unpack('<I', arg_bytes)[0]
                    out.append((offset, mnem, val, resolve_token(val) if mnem in TOKEN_OPS else f"0x{val:x}"))
                else:
                    val = int.from_bytes(arg_bytes, 'little')
                    out.append((offset, mnem, val, ""))
            continue
        if op not in OPCODES:
            out.append((offset, f'<unknown 0x{op:02x}>', None, ""))
            i += 1
            continue
        mnem, arg_size = OPCODES[op]
        i += 1
        if arg_size == 0:
            out.append((offset, mnem, None, ""))
        elif arg_size is None:
            count = struct.unpack('<I', code[i:i+4])[0]
            i += 4 + count*4
            out.append((offset, mnem, count, "switch"))
        else:
            arg_bytes = code[i:i+arg_size]
            i += arg_size
            if arg_size == 4:
                val = struct.unpack('<I', arg_bytes)[0]
                if mnem in TOKEN_OPS:
                    detail = resolve_token(val)
                elif mnem in LONG_BRANCH:
                    target = i + struct.unpack('<i', arg_bytes)[0]
                    detail = f"-> 0x{target:04x}"
                else:
                    detail = f"0x{val:x}"
                out.append((offset, mnem, val, detail))
            elif arg_size == 1:
                if mnem in SHORT_BRANCH or mnem == 'ldc.i4.s':
                    val = struct.unpack('<b', arg_bytes)[0]
                else:
                    val = arg_bytes[0]
                if mnem in SHORT_BRANCH:
                    target = i + val
                    out.append((offset, mnem, val, f"-> IL_{target:04x}"))
                else:
                    out.append((offset, mnem, val, ""))
            else:
                val = int.from_bytes(arg_bytes, 'little', signed=False)
                out.append((offset, mnem, val, ""))
    return out

def read_method_body(rva):
    offset = pe.get_offset_from_rva(rva)
    data = pe.__data__
    first = data[offset]
    if (first & 0x3) == 0x2:
        code_size = first >> 2
        return 1, code_size, data[offset+1:offset+1+code_size]
    elif (first & 0x3) == 0x3:
        flags_size = struct.unpack('<H', data[offset:offset+2])[0]
        header_size = (flags_size >> 12) * 4
        code_size = struct.unpack('<I', data[offset+4:offset+8])[0]
        return header_size, code_size, data[offset+header_size:offset+header_size+code_size]
    return 0, 0, b''

target_names = ['button1_Click', 'ComputeSerialNumberSum', 'ComputeSerial', 'ShiftSerial', 'ComputeName', 'textBox2_TextChanged', 'textBox1_TextChanged', '.ctor']
for method in mdt.MethodDef.rows:
    name = str(method.Name)
    if name in target_names:
        hsz, csz, code = read_method_body(method.Rva)
        print(f"\n=== {name} (CodeSize={csz}) ===")
        for offset, mnem, val, detail in disasm(code):
            print(f"  IL_{offset:04x}: {mnem:<14} {detail}")
