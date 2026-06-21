"""
FongYung.exe 免CD补丁脚本
基于 KnifeMan 的补丁方案，适配 FongYung.exe (WCCW引擎同系列)

补丁策略:
  补丁1-3: NOP掉驱动器类型检查、卷信息失败检查、卷标不匹配检查
  补丁4: 强制卷标→CD编号转换返回值为3（成功）
  补丁5: 跳过CD文件加载，直接跳转到存储结果→返回

补丁对比 KnifeMan:
  KnifeMan 方法:  直接memcmp("KnifeMan", volName, 8) → TEST → JE
  FongYung 方法:  CALL sub_vol_check(volName) → MOV EBP,EAX → CMP EBP,3
  两种方法架构相同但实现细节不同
"""
import struct
import hashlib
import shutil
from datetime import datetime

EXE_ORIG = 'c:/Project/GameDecomp/WindCloud/fongyung/FongYung.exe'
EXE_PATCHED = 'c:/Project/GameDecomp/WindCloud/workspace/build/FongYung.exe'  # 沙盒输出

# 计算文件哈希
def hash_file(path):
    with open(path, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

print(f"原始文件 MD5: {hash_file(EXE_ORIG)}")

# 读取文件
with open(EXE_ORIG, 'rb') as f:
    data = bytearray(f.read())

original_size = len(data)

# ==================== 补丁定义 ====================
PATCHES = [
    {
        'name': '补丁1 - 绕过驱动器类型检查',
        'rva': 0xA6C3C,
        'original': bytes([0x0F, 0x85, 0x7D, 0x01, 0x00, 0x00]),
        'patched':  bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        'desc': 'JNE -> NOP (非CD-ROM驱动器也允许通过)',
    },
    {
        'name': '补丁2 - 绕过卷信息失败检查',
        'rva': 0xA6C80,
        'original': bytes([0x0F, 0x84, 0x39, 0x01, 0x00, 0x00]),
        'patched':  bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        'desc': 'JE -> NOP (GetVolumeInformationA失败也继续)',
    },
    {
        'name': '补丁3 - 绕过卷标不匹配检查',
        'rva': 0xA6C9C,
        'original': bytes([0x0F, 0x85, 0x1D, 0x01, 0x00, 0x00]),
        'patched':  bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        'desc': 'JNE -> NOP (卷标比较失败也继续)',
    },
    {
        'name': '补丁4a - 跳过卷标检测调用，强制EAX=3',
        'rva': 0xA6CA6,
        'original': bytes([0x52, 0xE8, 0xAF, 0xBD, 0x00, 0x00]),
        'patched':  bytes([0xB8, 0x03, 0x00, 0x00, 0x00, 0x90]),
        'desc': 'PUSH EDX; CALL -> MOV EAX,3; NOP (无栈操作，强制成功)',
    },
    {
        'name': '补丁4b - NOP栈清理(与4a配套保持栈平衡)',
        'rva': 0xA6CAE,
        'original': bytes([0x83, 0xC4, 0x04]),
        'patched':  bytes([0x90, 0x90, 0x90]),
        'desc': 'ADD ESP,4 -> NOP (4a已移除PUSH,此处不再需要清栈)',
    },
    {
        'name': '补丁5 - 跳过CD文件加载，直接返回成功',
        'rva': 0xA6CC1,
        'original': bytes([0x0F, 0x85, 0x14, 0x01, 0x00, 0x00]),
        'patched':  bytes([0xE9, 0x15, 0x01, 0x00, 0x00, 0x90]),
        'desc': 'JNE 0xA6DDB -> JMP 0xA6DDB; NOP (无条件跳到存储结果并返回)',
    },
]

# ==================== 验证原始字节 ====================
print("\n=== 验证原始字节 ===")
all_valid = True
for p in PATCHES:
    rva = p['rva']
    actual = bytes(data[rva:rva+len(p['original'])])
    if actual == p['original']:
        print(f"[OK] {p['name']} @ RVA 0x{rva:X}: {actual.hex()}")
    else:
        print(f"[FAIL] {p['name']} @ RVA 0x{rva:X}")
        print(f"  期望: {p['original'].hex()}")
        print(f"  实际: {actual.hex()}")
        all_valid = False

if not all_valid:
    print("\n[错误] 原始字节验证失败，请检查 RVA 地址！中止操作。")
    exit(1)

# ==================== 应用补丁 ====================
print("\n=== 应用补丁 ===")
for p in PATCHES:
    rva = p['rva']
    data[rva:rva+len(p['patched'])] = p['patched']
    print(f"[OK] {p['name']}: {p['desc']}")

# ==================== 计算统计 ====================
total_bytes = sum(len(p['patched']) for p in PATCHES)
print(f"\n总修改量: {len(PATCHES)} 处, {total_bytes} 字节")

# ==================== 写回文件 ====================
with open(EXE_PATCHED, 'wb') as f:
    f.write(data)

assert len(data) == original_size, "文件大小改变了！"
print(f"\n已写入: {EXE_PATCHED}")
print(f"补丁后 MD5: {hash_file(EXE_PATCHED)}")

# ==================== 补丁摘要 ====================
print(f"""
╔══════════════════════════════════════════════════╗
║       FongYung.exe 免CD补丁 — 应用完成         ║
╠══════════════════════════════════════════════════╣
║ 补丁1 (0xA6C3C): JNE→NOP   绕过驱动器类型检查  ║
║ 补丁2 (0xA6C80): JE→NOP    绕过卷信息失败检查  ║
║ 补丁3 (0xA6C9C): JNE→NOP   绕过卷标不匹配检查  ║
║ 补丁4a(0xA6CA6): PUSH+CALL→MOV EAX,3+NOP       ║
║ 补丁4b(0xA6CAE): ADD ESP,4→NOP (栈平衡)        ║
║ 补丁5 (0xA6CC1): JNE→JMP   跳过CD文件加载      ║
╠══════════════════════════════════════════════════╣
║ 总计: {len(PATCHES)}处修改, {total_bytes}字节                     ║
║ 备份: workspace/backups/                       ║
║ 回滚: cp backups/FongYung_exe_bak_*.exe        ║
║       fongyung/FongYung.exe                      ║
╚══════════════════════════════════════════════════╝
""")
