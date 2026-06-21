"""
精确反汇编 FongYung.exe 的 CD 检查函数
定位所有 7 个补丁的对应地址
"""
import struct

EXE_PATH = 'c:/Project/GameDecomp/WindCloud/fongyung/FongYung.exe'
with open(EXE_PATH, 'rb') as f:
    data = bytearray(f.read())

# PE info from prior analysis
IMAGE_BASE = 0x00400000
TEXT_START = 0x1000  # .text roff

# Key IAT addresses from v3
IAT = {
    'GetDriveTypeA':       0x004C8154,
    'GetVolumeInformationA': 0x004C8158,
    'GetLogicalDrives':    0x004C8160,
}

# Read function bytes - starting from well before the GetLogicalDrives call
# GetLogicalDrives CALL is at RVA 0xA6BED
# Function prologue should be ~20 bytes before that

func_start_rva = 0xA6BDB  # based on pre-context analysis
func_end_estimate = 0xA6D00  # generous end

# Read the function bytes
text_start = TEXT_START
func_file_start = func_start_rva  # for .text, rva == file offset (both start at 0x1000)
func_bytes = data[func_file_start:func_file_start + 0x200]

print(f"CD Check function: RVA 0x{func_start_rva:X} - 0x{func_start_rva + 0x200:X}")
print(f"Function bytes ({len(func_bytes)} bytes)")

# Manual disassembly of critical parts
def disasm_one(offset, raw_bytes):
    """Simple disassembly helper - decodes common x86 instructions"""
    b = raw_bytes
    rva = func_start_rva + offset
    file_off = func_file_start + offset

    # MOV EBX, ECX (thiscall convention)
    if b[0] == 0x8B and b[1] == 0xD9:
        return f"MOV EBX, ECX", 2

    # CALL [imm32]
    if b[0] == 0xFF and b[1] == 0x15:
        addr = struct.unpack_from('<I', b, 2)[0]
        name = "?"
        for n, va in IAT.items():
            if va == addr:
                name = n
                break
        return f"CALL [{name} (0x{addr:08X})]", 6

    # CALL rel32
    if b[0] == 0xE8:
        rel = struct.unpack_from('<i', b, 1)[0]
        target = rva + 5 + rel
        return f"CALL 0x{target & 0xFFFFFFFF:08X}", 5

    # PUSH imm32
    if b[0] == 0x68:
        imm = struct.unpack_from('<I', b, 1)[0]
        # Check if this is a known string address
        comment = ""
        if imm == 0x004D9D4C or imm == 0x004D9E3C:
            comment = f" ; 'FongYung'"
        elif 0x004D9B00 <= imm <= 0x004D9D00:
            comment = f" ; '%c:\\...'"
        return f"PUSH 0x{imm:08X}{comment}", 5

    # PUSH imm8
    if b[0] == 0x6A:
        imm = b[1]
        return f"PUSH 0x{imm:X}", 2

    # PUSH reg
    if b[0] in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
        regs = {0x50:'EAX', 0x51:'ECX', 0x52:'EDX', 0x53:'EBX', 0x54:'ESP', 0x55:'EBP', 0x56:'ESI', 0x57:'EDI'}
        return f"PUSH {regs[b[0]]}", 1

    # POP reg
    if b[0] in (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):
        regs = {0x58:'EAX', 0x59:'ECX', 0x5A:'EDX', 0x5B:'EBX', 0x5C:'ESP', 0x5D:'EBP', 0x5E:'ESI', 0x5F:'EDI'}
        return f"POP {regs[b[0]]}", 1

    # CMP EAX, imm8
    if b[0] == 0x83 and b[1] == 0xF8:
        imm = b[2]
        return f"CMP EAX, 0x{imm:X}", 3

    # CMP EAX, imm32
    if b[0] == 0x3D:
        imm = struct.unpack_from('<I', b, 1)[0]
        return f"CMP EAX, 0x{imm:X}", 5

    # CMP reg, imm8
    if b[0] == 0x83 and b[1] in (0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
        regs = {0xF9:'ECX', 0xFA:'EDX', 0xFB:'EBX', 0xFC:'ESP', 0xFD:'EBP', 0xFE:'ESI', 0xFF:'EDI'}
        imm = b[2]
        return f"CMP {regs[b[1]]}, 0x{imm:X}", 3

    # CMP EAX, imm32
    if b[0] == 0x83 and b[1] == 0xF8:
        return f"CMP EAX, {b[2]}", 3

    # JNE rel8
    if b[0] == 0x75:
        rel = b[1] if b[1] < 0x80 else b[1] - 256
        target = rva + 2 + rel
        return f"JNE 0x{target:X}", 2

    # JE rel8
    if b[0] == 0x74:
        rel = b[1] if b[1] < 0x80 else b[1] - 256
        target = rva + 2 + rel
        return f"JE 0x{target:X}", 2

    # JMP rel8
    if b[0] == 0xEB:
        rel = b[1] if b[1] < 0x80 else b[1] - 256
        target = rva + 2 + rel
        return f"JMP 0x{target:X}", 2

    # JMP rel32
    if b[0] == 0xE9:
        rel = struct.unpack_from('<i', b, 1)[0]
        target = rva + 5 + rel
        return f"JMP 0x{target:X}", 5

    # JE rel32 (0F 84)
    if b[0] == 0x0F and b[1] == 0x84:
        rel = struct.unpack_from('<i', b, 2)[0]
        target = rva + 6 + rel
        return f"JE 0x{target:X}", 6

    # JNE rel32 (0F 85)
    if b[0] == 0x0F and b[1] == 0x85:
        rel = struct.unpack_from('<i', b, 2)[0]
        target = rva + 6 + rel
        return f"JNE 0x{target:X}", 6

    # TEST EAX, EAX
    if b[0] == 0x85 and b[1] == 0xC0:
        return "TEST EAX, EAX", 2

    # XOR EAX, EAX
    if b[0] == 0x33 and b[1] == 0xC0:
        return "XOR EAX, EAX", 2

    # MOV EAX, imm32
    if b[0] == 0xB8:
        imm = struct.unpack_from('<I', b, 1)[0]
        return f"MOV EAX, 0x{imm:X}", 5

    # ADD ESP, imm8
    if b[0] == 0x83 and b[1] == 0xC4:
        return f"ADD ESP, 0x{b[2]:X}", 3

    # ADD EDI, imm8
    if b[0] == 0x83 and b[1] == 0xC7:
        return f"ADD EDI, 0x{b[2]:X}", 3

    # SUB ESP, imm32
    if b[0] == 0x81 and b[1] == 0xEC:
        imm = struct.unpack_from('<I', b, 2)[0]
        return f"SUB ESP, 0x{imm:X}", 6

    # MOV [EBX+disp8], reg
    if b[0] == 0x89:
        modrm = b[1]
        if (modrm >> 6) == 1 and (modrm & 7) == 3:  # [EBX+disp8]
            reg = (modrm >> 3) & 7
            disp = b[2]
            regs8 = {0:'EAX', 1:'ECX', 2:'EDX', 3:'EBX', 4:'ESP', 5:'EBP', 6:'ESI', 7:'EDI'}
            reg_name = regs8.get(reg, f'R{reg}')
            return f"MOV [EBX+0x{disp:X}], {reg_name}", 3

    # MOV [EBX+disp8], EAX (special case of above)
    if b[0] == 0x89 and b[1] == 0x43:
        disp = b[2]
        return f"MOV [EBX+0x{disp:X}], EAX", 3

    # LEA
    if b[0] == 0x8D:
        modrm = b[1]
        if modrm == 0x44 and b[2] == 0x24:  # LEA EAX, [ESP+disp8]
            disp = b[3]
            return f"LEA EAX, [ESP+0x{disp:X}]", 4
        if modrm == 0x4C and b[2] == 0x24:  # LEA ECX, [ESP+disp8]
            disp = b[3]
            return f"LEA ECX, [ESP+0x{disp:X}]", 4
        if modrm == 0x54 and b[2] == 0x24:  # LEA EDX, [ESP+disp8]
            disp = b[3]
            return f"LEA EDX, [ESP+0x{disp:X}]", 4
        if modrm == 0x84 and b[2] == 0x24:  # LEA EAX, [ESP+disp32]
            disp = struct.unpack_from('<I', b, 3)[0]
            return f"LEA EAX, [ESP+0x{disp:X}]", 7
        if modrm == 0x94 and b[2] == 0x24:  # LEA EDX, [ESP+disp32]
            disp = struct.unpack_from('<I', b, 3)[0]
            return f"LEA EDX, [ESP+0x{disp:X}]", 7
        if modrm == 0x8C and b[2] == 0x24:  # LEA ECX, [ESP+disp32]
            disp = struct.unpack_from('<I', b, 3)[0]
            return f"LEA ECX, [ESP+0x{disp:X}]", 7

    # MOV dword [ESP+disp8], imm32
    if b[0] == 0xC7 and b[1] == 0x44 and b[2] == 0x24:
        disp = b[3]
        imm = struct.unpack_from('<I', b, 4)[0]
        return f"MOV DWORD [ESP+0x{disp:X}], 0x{imm:X}", 8

    # MOV [reg+disp8], imm
    if b[0] == 0xC7:
        modrm = b[1]
        if (modrm >> 6) == 1:  # [reg+disp8]
            reg = modrm & 7
            disp = b[2]
            imm = struct.unpack_from('<I', b, 3)[0]
            regs8 = {0:'EAX', 1:'ECX', 2:'EDX', 3:'EBX', 4:'ESP', 5:'EBP', 6:'ESI', 7:'EDI'}
            reg_name = regs8.get(reg, f'R{reg}')
            return f"MOV DWORD [{reg_name}+0x{disp:X}], 0x{imm:X}", 7

    # NOP
    if b[0] == 0x90:
        return "NOP", 1

    # RET
    if b[0] == 0xC3:
        return "RET", 1

    # INC reg
    if b[0] in (0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47):
        regs = {0x40:'EAX', 0x41:'ECX', 0x42:'EDX', 0x43:'EBX', 0x44:'ESP', 0x45:'EBP', 0x46:'ESI', 0x47:'EDI'}
        return f"INC {regs[b[0]]}", 1

    # DEC reg
    if b[0] in (0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F):
        regs = {0x48:'EAX', 0x49:'ECX', 0x4A:'EDX', 0x4B:'EBX', 0x4C:'ESP', 0x4D:'EBP', 0x4E:'ESI', 0x4F:'EDI'}
        return f"DEC {regs[b[0]]}", 1

    # SHL EAX, CL
    if b[0] == 0xD3 and b[1] == 0xE0:
        return "SHL EAX, CL", 2

    # AND/OR/XOR
    if b[0] == 0x85 and b[1] == 0xFF:
        return "TEST EDI, EDI", 2

    # TEST reg, reg
    if b[0] == 0x85:
        rm = b[1]
        if rm == 0xC9: return "TEST ECX, ECX", 2
        if rm == 0xD2: return "TEST EDX, EDX", 2
        if rm == 0xDB: return "TEST EBX, EBX", 2
        if rm == 0xE4: return "TEST ESP, ESP", 2
        if rm == 0xED: return "TEST EBP, EBP", 2
        if rm == 0xF6: return "TEST ESI, ESI", 2
        if rm == 0xFF: return "TEST EDI, EDI", 2
        if rm == 0xC0: return "TEST EAX, EAX", 2

    # MOV reg, imm32
    if b[0] in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
        regs = {0xB8:'EAX', 0xB9:'ECX', 0xBA:'EDX', 0xBB:'EBX', 0xBC:'ESP', 0xBD:'EBP', 0xBE:'ESI', 0xBF:'EDI'}
        imm = struct.unpack_from('<I', b, 1)[0]
        return f"MOV {regs[b[0]]}, 0x{imm:X}", 5

    # MOV reg, reg
    if b[0] == 0x8B:
        src = (b[1] >> 3) & 7
        dst = b[1] & 7
        regs = {0:'EAX', 1:'ECX', 2:'EDX', 3:'EBX', 4:'ESP', 5:'EBP', 6:'ESI', 7:'EDI'}
        reg_name = f"{regs[dst]}, {regs[src]}"
        return f"MOV {reg_name}", 2

    # CMP reg, reg (3B)
    if b[0] == 0x3B:
        src = (b[1] >> 3) & 7
        dst = b[1] & 7
        regs = {0:'EAX', 1:'ECX', 2:'EDX', 3:'EBX', 4:'ESP', 5:'EBP', 6:'ESI', 7:'EDI'}
        return f"CMP {regs[dst]}, {regs[src]}", 2

    # SHL (standard form)
    if b[0] == 0xC1 and (b[1] >> 3) & 7 == 4:  # SHL
        reg = b[1] & 7
        shift = b[2]
        regs = {0:'EAX', 1:'ECX', 2:'EDX', 3:'EBX', 4:'ESP', 5:'EBP', 6:'ESI', 7:'EDI'}
        return f"SHL {regs[reg]}, {shift}", 3

    return f"??? {' '.join(f'{x:02x}' for x in b[:min(8, len(b))])}", 1

# Scan and annotate the function
offset = 0
print(f"\n--- CD Check Function Disassembly ---")
print(f"{'RVA':>8s}  {'File':>8s}  {'Bytes':<24s}  Instruction")
print(f"{'='*8}  {'='*8}  {'='*24}  {'='*40}")

# Mark known important locations
known_ias = {v: k for k, v in IAT.items()}

# Find all interesting spots in the function
interesting_rvas = {}

while offset < len(func_bytes):
    rva = func_start_rva + offset
    file_off = func_file_start + offset

    try:
        instr, length = disasm_one(offset, func_bytes[offset:offset+15])
    except Exception as e:
        instr = f"ERROR: {e}"
        length = 1

    raw = func_bytes[offset:offset+length]
    hex_str = ' '.join(f'{b:02x}' for b in raw)

    # Mark interesting instructions
    marker = ""
    lo_instr = instr.lower()

    if 'getdrivetypea' in lo_instr:
        marker = " <-- ★ [补丁1相关] GetDriveTypeA CALL"
        interesting_rvas['GetDriveTypeA_CALL'] = rva
    elif 'getvolumeinformationa' in lo_instr:
        marker = " <-- ★ [补丁2相关] GetVolumeInformationA CALL"
        interesting_rvas['GetVolumeInformationA_CALL'] = rva
    elif 'getlogicaldrives' in lo_instr:
        marker = " <-- ★ GetLogicalDrives CALL"
        interesting_rvas['GetLogicalDrives_CALL'] = rva
    elif 'jne 0x' in lo_instr and 'eax, 0x5' in instr_prev:
        marker = " <-- ★ [补丁1候选] 非CD-ROM跳过"
        interesting_rvas['Patch1_JNE'] = rva
    elif 'cmp eax, 0x5' in lo_instr:
        marker = " <-- ★ [补丁1范围] 比较驱动器类型"
    elif 'test eax, eax' in lo_instr and any('je 0x' in lo_instr for _ in [1]):
        pass  # too generic
    elif instr.startswith('JE 0x') and 'getvolumeinformationa' in prev_context:
        marker = " <-- ★ [补丁2候选] 卷信息失败跳过"
        interesting_rvas['Patch2_JE'] = rva
    elif 'test eax, eax' in lo_instr and 'fongyung' in prev_context:
        marker = " <-- ★ [补丁3候选] 卷标比较结果TEST"
        interesting_rvas['Patch3_TEST'] = rva
    elif "'fongyung'" in lo_instr.lower():
        marker = " <-- ★ [补丁3相关] PUSH CD卷标"
        interesting_rvas['Push_FongYung'] = rva
    elif 'push 0x8' in lo_instr or 'push 0x8\n' in lo_instr:
        marker = " <-- ★ [补丁3相关] PUSH 比较长度8"
        interesting_rvas['Push_Length8'] = rva
    elif 'je 0x' in lo_instr and 'test eax, eax' in instr_prev:
        marker = " <-- ★ [补丁3相关] 卷标匹配→跳转"
    elif 'cmp eax, 0x3' in lo_instr:
        marker = " <-- ★ [补丁4相关] 检查结果==3?"
        interesting_rvas['CMP_EAX_3'] = rva
    elif 'cmp eax, 0x4' in lo_instr:
        marker = " <-- ★ [补丁4相关] 检查结果==4?"
        interesting_rvas['CMP_EAX_4'] = rva
    elif 'add edi, 0x41' in lo_instr:
        marker = " <-- ★ [补丁4相关] 盘符ASCII转换"
    elif 'mov [ebx+0x' in lo_instr and 'eax' in lo_instr and ('c' in instr.split('+0x')[1][:3].lower() or '8' in instr.split('+0x')[1][:3]):
        marker = " <-- ★ [补丁4相关] 存储结果到对象"

    print(f"0x{rva:06X}  0x{file_off:06X}  {hex_str:<24s}  {instr}{marker}")

    instr_prev = instr
    if 'fongyung' in instr_prev.lower():
        prev_context = 'fongyung'
    elif 'getvolumeinformationa' in instr_prev.lower():
        prev_context = 'getvolumeinformationa'
    else:
        prev_context = ''

    offset += length

print(f"\n--- 关键地址汇总 ---")
for k, v in interesting_rvas.items():
    print(f"  {k}: RVA=0x{v:X}, File=0x{v:X}")

# ============== Part 2: 搜索启动对话框和游戏内对话框 ==============
print(f"\n===== 第二部分：对话框补丁定位 =====")

# 搜索 "insertcd" 或类似字符串
for pat in [b'insertcd', b'cdinsert', b'CD', b'cd', b'sertcd']:
    pos = 0
    while True:
        pos = data.find(pat, pos)
        if pos == -1:
            break
        rva = pos  # rough, but for .text section
        # Try to find the exact section
        for sec_name, sec_vaddr, sec_roff, sec_size in [
            ('.text', 0x1000, 0x1000, 0xC7000),
            ('.rdata', 0xC8000, 0xC8000, 0xD000),
            ('.data', 0xD5000, 0xD5000, 0x9000),
        ]:
            if sec_roff <= pos < sec_roff + sec_size:
                rva = pos - sec_roff + sec_vaddr
                break
        ctx = data[max(0,pos-4):min(len(data),pos+16)]
        try:
            ctx_str = ctx.decode('ascii', errors='replace')
            if any(c.isprintable() or c in '\x00' for c in ctx_str):
                print(f"  '{pat.decode()}' at file=0x{pos:X}, RVA=0x{rva:X}: '{ctx_str}'")
        except:
            pass
        pos += 1

# 搜索 "insertcd2" - KnifeMan 中使用的脚本命令
print(f"\n搜索脚本CD相关命令:")
for pat in [b'insertcd', b'insert', b'cd_check', b'cdcheck', b'CDCHECK']:
    pos = data.find(pat)
    if pos >= 0:
        ctx = data[max(0,pos-4):min(len(data),pos+20)]
        try:
            print(f"  '{pat.decode()}' at file=0x{pos:X}: {ctx}")
        except:
            print(f"  '{pat.hex()}' at file=0x{pos:X}: {ctx.hex()}")

# 搜索启动对话框特征 - 在 KnifeMan 中调用链: startup_init -> prepare_cd_dialog -> insertcd2_handler
# 搜索可能调用 CD对话框的 CALL 模式
# 在 KnifeMan 中，补丁6是 NOP掉启动时的 CALL (在某个初始化函数中)
# 补丁7是游戏内条件检查 (JE → JMP)
print(f"\n注意：对话框补丁依赖于对游戏脚本系统和对话框系统的理解。")
print(f"需要找到调用 CD检查结果 (obj+0xC) 的代码。")

# 搜索对 [EBX+0xC] 或 [reg+0xC] 的访问
print(f"\n搜索对 CD检查结果 [this+0xC] 的访问:")
for offset_val in [0xC, 0x8, 0x4]:
    # MOV EAX, [reg+offset]
    # 8B 43 0C = MOV EAX, [EBX+0xC]
    # 8B 46 0C = MOV EAX, [ESI+0xC]
    for reg_byte in [0x43, 0x46, 0x44, 0x45, 0x47, 0x4E, 0x4F]:  # [EBX], [ESI], [ESP], [EBP], [EDI], [ESI], [EDI]
        if reg_byte == 0x44:  # ESP+offset doesn't make sense here
            continue
        pattern = bytes([0x8B, reg_byte, offset_val])
        pos = 0
        text_data = data[0x1000:0x1000 + 0xC7000]
        while True:
            pos = text_data.find(pattern, pos)
            if pos == -1:
                break
            foff = 0x1000 + pos
            rva = foff  # for .text
            reg_name = {0x43: 'EBX', 0x46: 'ESI', 0x45: 'EBP', 0x47: 'EDI', 0x4E: 'ESI', 0x4F: 'EDI'}[reg_byte]
            if offset_val == 0xC and any(r in text_data[pos-20:pos+20] for r in [b'\x83\xf8\x03', b'\x83\xf9\x03', b'\x83\xfa\x03']):
                ctx = text_data[max(0,pos-10):min(len(text_data),pos+15)]
                print(f"  MOV EAX, [{reg_name}+0x{offset_val:X}] at RVA 0x{rva:X} (near CMP X,3): {ctx.hex()}")
                # Don't break, keep searching
            if offset_val == 0xC and all(b not in text_data[pos-3:pos] for b in [b'\xC7']):  # Not part of MOV DWORD
                ctx = text_data[max(0,pos-10):min(len(text_data),pos+15)]
                # Only show if it's used in a meaningful way (followed by CMP or access)
                after = text_data[pos+3:pos+10]
                if any(after.startswith(b) for b in [b'\x83\xf8', b'\x85\xc0', b'\x3d', b'\x50', b'\x3b']):
                    print(f"  MOV EAX, [{reg_name}+0x{offset_val:X}] at RVA 0x{rva:X} (active use): {ctx.hex()}")
            pos += 1

print(f"\n===== 分析完成 =====")
