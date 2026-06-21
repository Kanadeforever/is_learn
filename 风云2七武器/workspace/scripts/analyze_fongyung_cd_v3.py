"""
FongYung.exe CD检查函数定位 v3 - 直接字节签名搜索
匹配与 KnifeMan 相同的代码模式
"""
import struct

EXE_PATH = 'c:/Project/GameDecomp/WindCloud/fongyung/FongYung.exe'

with open(EXE_PATH, 'rb') as f:
    data = bytearray(f.read())

# PE Sections (pre-computed from v2 output)
SECTIONS = [
    {'name': '.text',  'vaddr': 0x01000, 'vsize': 0xC6FD8, 'roff': 0x01000, 'rsize': 0xC7000},
    {'name': '.rdata', 'vaddr': 0xC8000, 'vsize': 0xC100,  'roff': 0xC8000, 'rsize': 0xD000},
    {'name': '.data',  'vaddr': 0xD5000, 'vsize': 0x2950C, 'roff': 0xD5000, 'rsize': 0x9000},
    {'name': '.rsrc',  'vaddr': 0xFF000, 'vsize': 0xC88,   'roff': 0xDE000, 'rsize': 0x1000},
]
IMAGE_BASE = 0x00400000

def rva_to_file(rva):
    for sec in SECTIONS:
        if sec['vaddr'] <= rva < sec['vaddr'] + max(sec['vsize'], sec['rsize']):
            return rva - sec['vaddr'] + sec['roff']
    return None

def file_to_rva(foff):
    for sec in SECTIONS:
        if sec['roff'] <= foff < sec['roff'] + sec['rsize']:
            return foff - sec['roff'] + sec['vaddr']
    return None

text_start = SECTIONS[0]['roff']
text_end = text_start + SECTIONS[0]['rsize']
text_data = data[text_start:text_end]

# ============== Step 1: 找 GET imported function IAT addresses ==============
# Search for function name strings in the import names area (.rdata)
# "GetDriveTypeA\0", "GetVolumeInformationA\0", "GetLogicalDrives\0"
# These are referenced by IMAGE_IMPORT_BY_NAME entries

def find_str_in_section(sec_name, search_str):
    """Find a string in a specific section, return all offsets"""
    sec = [s for s in SECTIONS if s['name'] == sec_name][0]
    sec_data = data[sec['roff']:sec['roff']+sec['rsize']]
    results = []
    pos = 0
    target = search_str.encode('ascii') + b'\x00'
    while True:
        pos = sec_data.find(target, pos)
        if pos == -1:
            break
        results.append(sec['roff'] + pos)
        pos += 1
    return results

for fn in ['GetDriveTypeA', 'GetVolumeInformationA', 'GetLogicalDrives']:
    hits = find_str_in_section('.rdata', fn)
    if hits:
        rva = file_to_rva(hits[0])
        print(f"{fn}: file offsets = {[hex(h) for h in hits]}, first RVA = 0x{rva:X}")
        # The import hint is 2 bytes before the name string
        # The IAT entry itself is in a different location
        # Let's check the 4 bytes before the hint+name (this is the import lookup table entry)
        # Actually each entry in the import name table points to where hint+name is stored

# ============== Step 2: 直接搜索 FF 15 调用模式 ==============
# 收集所有 FF 15 XX XX XX XX 的调用，其中 XX XX XX XX 是目标 VA
print("\n=== All FF 15 indirect calls: ===")
ff15_calls = []
pos = 0
targets = set()
while pos < len(text_data) - 5:
    if text_data[pos] == 0xFF and text_data[pos+1] == 0x15:
        addr = struct.unpack_from('<I', text_data, pos+2)[0]
        foff = text_start + pos
        rva = file_to_rva(foff)
        ff15_calls.append({'file_off': foff, 'rva': rva, 'target_va': addr})
        targets.add(addr)
    pos += 1

print(f"Total FF 15 calls: {len(ff15_calls)}")
print(f"Unique target VAs: {len(targets)}")

# Categorize targets by section
for tgt in sorted(targets):
    tgt_rva = tgt - IMAGE_BASE if tgt >= IMAGE_BASE else tgt
    # Determine which section
    sec_name = "?"
    for sec in SECTIONS:
        if sec['vaddr'] <= tgt_rva < sec['vaddr'] + max(sec['vsize'], sec['rsize']):
            sec_name = sec['name']
            break
    if sec_name == '.rdata' or sec_name == '.data':
        # These are likely IAT entries
        print(f"  IAT target: VA=0x{tgt:08X} (RVA=0x{tgt_rva:X}) in {sec_name}")

# ============== Step 3: 通过 IAT 正确定位 ==============
# Parse the import directory properly this time
# DataDirectory[1] (Import) is at optional_header + 104 (for PE32)
# Wait, DataDirectory starts at opt + 96. Import table is index 1.
# Each IMAGE_DATA_DIRECTORY is 8 bytes (RVA, Size)
# So Import is at offset: opt + 96 + 1*8 = opt + 104

# Re-parse PE more carefully
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
# Read COFF
machine, num_sections, timedate, symtab, nsyms, size_opt_hdr, characteristics = \
    struct.unpack_from('<HHIIIHH', data, coff)
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]

# DataDirectory
import_dir_rva = struct.unpack_from('<I', data, opt + 104)[0]  # offset 104 = 96 + 8
import_dir_size = struct.unpack_from('<I', data, opt + 108)[0]
print(f"\nImport Directory: RVA=0x{import_dir_rva:X}, Size=0x{import_dir_size:X}")

import_dir_foff = rva_to_file(import_dir_rva)
print(f"Import Directory file offset: 0x{import_dir_foff:X}")

if import_dir_foff:
    idx = 0
    iat_map = {}
    while True:
        entry_off = import_dir_foff + idx * 20
        if entry_off + 20 > len(data):
            break

        oft_rva = struct.unpack_from('<I', data, entry_off)[0]       # OriginalFirstThunk
        td = struct.unpack_from('<I', data, entry_off + 4)[0]        # TimeDateStamp
        name_rva = struct.unpack_from('<I', data, entry_off + 12)[0] # Name
        iat_rva_base = struct.unpack_from('<I', data, entry_off + 16)[0]  # FirstThunk

        if oft_rva == 0 and iat_rva_base == 0:
            break

        # Get DLL name
        dll_name_off = rva_to_file(name_rva)
        dll_name = ""
        if dll_name_off:
            null_pos = data.find(b'\x00', dll_name_off)
            dll_name = data[dll_name_off:null_pos].decode('ascii', errors='replace')

        # Read thunks
        thunk_rva = oft_rva if oft_rva else iat_rva_base
        thunk_off = rva_to_file(thunk_rva)
        if not thunk_off:
            idx += 1
            continue

        ti = 0
        while True:
            to = thunk_off + ti * 4
            if to + 4 > len(data):
                break
            val = struct.unpack_from('<I', data, to)[0]
            if val == 0:
                break

            if val & 0x80000000:
                ordinal = val & 0xFFFF
                fn = f"Ordinal_{ordinal}"
            else:
                # val is RVA to IMAGE_IMPORT_BY_NAME (hint word + name)
                hint_name_off = rva_to_file(val & 0x7FFFFFFF)
                if hint_name_off:
                    hint = struct.unpack_from('<H', data, hint_name_off)[0]
                    null_pos = data.find(b'\x00', hint_name_off + 2)
                    fn = data[hint_name_off+2:null_pos].decode('ascii', errors='replace')
                else:
                    fn = f"Unknown_{val:08X}"

            # IAT entry address
            iat_rva = iat_rva_base + ti * 4
            iat_va = IMAGE_BASE + iat_rva
            iat_map[fn] = {'dll': dll_name, 'iat_rva': iat_rva, 'iat_va': iat_va}
            ti += 1

        idx += 1

    print(f"\nParsed {len(iat_map)} imported functions from {idx} DLLs")

    # Display key functions
    key_funcs = ['GetDriveTypeA', 'GetVolumeInformationA', 'GetLogicalDrives']
    print("\n=== Key CD check functions ===")
    for fn in key_funcs:
        if fn in iat_map:
            info = iat_map[fn]
            print(f"  {fn}: IAT_RVA=0x{info['iat_rva']:X}, IAT_VA=0x{info['iat_va']:08X}, DLL={info['dll']}")
        else:
            print(f"  {fn}: NOT FOUND")

    # ============== Step 4: 搜索 CD 检查函数 ==============
    print("\n=== CD check function candidate search ===")

    # Find all calls to GetDriveTypeA, GetVolumeInformationA, GetLogicalDrives
    for fn in key_funcs:
        if fn not in iat_map:
            continue
        iat_va = iat_map[fn]['iat_va']
        call_sig = struct.pack('<BI', 0x15, iat_va)  # FF 15 [iat_va]
        pos = 0
        found = []
        while pos < len(text_data) - 6:
            pos = text_data.find(call_sig, pos)
            if pos == -1:
                break
            foff = text_start + pos
            rva = file_to_rva(foff) or 0
            found.append((foff, rva))
            pos += 1
        print(f"\n{fn}: {len(found)} call sites")
        for foff, rva in found:
            # Show context around the call
            ctx_start = max(0, foff - 30)
            ctx_end = min(len(data), foff + 6)
            ctx = data[ctx_start:ctx_end]
            print(f"  CALL at file=0x{foff:X}, RVA=0x{rva:X}")
            print(f"    Pre-context bytes: {ctx.hex()}")

else:
    print("ERROR: Cannot resolve import directory to file offset")

# ============== Step 5: 搜索 PUSH 8 + strncmp 模式 ==============
print("\n=== Searching for PUSH 8 + memcmp/strncmp pattern ===")
# In KnifeMan: PUSH 8; PUSH buf; PUSH "KnifeMan"; CALL strncmp; ADD ESP,0xC; TEST EAX,EAX; JE found
# 6A 08 - PUSH 8
# 8D 4C 24 XX or similar - LEA ECX, [ESP+XX]
# 68 XX XX XX XX - PUSH "FongYung"
# E8 XX XX XX XX - CALL memcmp/strncmp
# 83 C4 0C - ADD ESP, 0C
# 85 C0 - TEST EAX, EAX
# 74 XX - JE found

# Search for "6A 08 ... 83 C4 0C ... 85 C0 ... 74"
pos = 0
matches = 0
while pos < len(text_data) - 12 and matches < 20:
    if text_data[pos] == 0x6A and text_data[pos+1] == 0x08:  # PUSH 8
        # Look ahead up to 20 bytes for ADD ESP, 0C + TEST EAX, EAX + JE
        ahead = text_data[pos+2:pos+22]
        add_idx = ahead.find(b'\x83\xC4\x0C')  # ADD ESP, 0C
        test_idx = ahead.find(b'\x85\xC0')      # TEST EAX, EAX
        if add_idx >= 0 and test_idx > add_idx:
            je_off = test_idx + 2
            if je_off < len(ahead) and (ahead[je_off] == 0x74 or ahead[je_off] == 0x0F):
                foff = text_start + pos
                rva = file_to_rva(foff)
                print(f"  PUSH 8 + memcmp/strncmp pattern at file=0x{foff:X}, RVA=0x{rva:X}")
                ctx = text_data[max(0,pos-20):min(len(text_data),pos+30)]
                print(f"    Context: {ctx.hex()}")
                matches += 1
    pos += 1

print("\n=== Analysis complete ===")
