# -*- coding: utf-8 -*-
"""
水浒传 MD 简易版 v9 —— 修复 v8 的 cmpa 编码 bug（2026-11-18）
v8 死因（铁证）:
  B5C9 按 M68k 编码手册 = cmpa.l (a1),a2 —— 内存间接比较, 不是寄存器比较!
  stub 里 a1=$FFEA80 是敌方槽基地址, 菜单阶段该内存=0 → a2>=0 恒成立
  → 所有调用全判敌方 → v8 完全是 no-op。capstone 渲染 "cmpa.l a1, a2"
  (不带括号) 误导了判断。
v9 修复:
  弃用 cmpa, 改用数据寄存器比较(语义无歧义):
    move.w a2,d1        ; 320A — 所有调用点 a2 都是 $00FFxxxx, 取低字
    cmpi.w #$EA80,d1    ; 0C41 EA80 — d1-imm, 无符号
    bcc/bhs → 原版表(敌方槽12+: 低字 >= $EA80)
  d1 安全性(双重): ① 函数体钩子后第一句 clr.w d1 先写后读
                  ② 函数出口 movem.l (a7)+,d0-d7/a2-a6 全部恢复
  其余(经验x3/金币x3/增强表/全9表)与 v8 相同。
"""
import struct, hashlib, json, os, sys

# 可移植入口: python build_v9.py <原版ROM路径> [输出目录]
# 未传参数时默认取当前目录下的 shz.md, 输出到 ./build
ROM_IN  = sys.argv[1] if len(sys.argv) > 1 else "shz.md"
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else os.path.join(".", "build")
os.makedirs(OUT_DIR, exist_ok=True)

data = bytearray(open(ROM_IN, "rb").read())
assert len(data) == 0x200000, "ROM size unexpected"
orig = bytes(data)
assert all(b == 0xFF for b in orig[0x1C0700:0x1C1000]), "空白区非全FF"

changes = []
def patch(addr, new_bytes, desc):
    old = bytes(data[addr:addr+len(new_bytes)])
    nb = bytes(new_bytes)
    data[addr:addr+len(nb)] = nb
    changes.append((addr, old.hex(), nb.hex(), desc))

# ---------- 1. 经验获取表 0x5F08 x3, clamp 100 ----------
EXP_ADDR, EXP_LEN = 0x5F08, 27
patch(EXP_ADDR, bytes(min(v*3, 100) for v in orig[EXP_ADDR:EXP_ADDR+EXP_LEN]),
      "经验获取表27B x3 clamp100")

# ---------- 2. 金币过关奖励表 0x11B20 19长字 x3 ----------
GOLD_ADDR, GOLD_LEN = 0x11B20, 76
vals = [struct.unpack('>I', orig[GOLD_ADDR+i*4:GOLD_ADDR+i*4+4])[0] for i in range(19)]
patch(GOLD_ADDR, b"".join(struct.pack('>I', v*3) for v in vals), "金币过关奖励19项 x3")

# ---------- 3. 增强参数块 + 跳表 ----------
PT_PTRS = 0x14DAA
ptrs = [struct.unpack('>I', orig[PT_PTRS+i*4:PT_PTRS+i*4+4])[0] for i in range(15)]
def enhance_block(blk, atk_init_override=None):
    out = bytearray(blk)
    for gi, mul in ((0,3),(1,3),(2,3),(3,2),(4,2),(6,2)):
        b = gi*4
        if gi <= 2:
            out[b] = min(blk[b]*2+5, 255)
        out[b+1] = min(blk[b+1]*mul, 255)
        out[b+3] = 255
    if atk_init_override is not None:
        out[4] = atk_init_override
    return bytes(out)

ENH_PARAMS, ENH_JUMPTAB = 0x1C0A00, 0x1C09C0
enh_official = bytearray(); enh_verify = bytearray()
for p in ptrs:
    blk = orig[p:p+0x20]
    enh_official += enhance_block(blk)
    enh_verify   += enhance_block(blk, atk_init_override=250)
patch(ENH_PARAMS, enh_official, "增强参数480B -> 0x1C0A00")
patch(ENH_JUMPTAB, b"".join(struct.pack('>I', ENH_PARAMS+i*0x20) for i in range(15)),
      "增强跳表15项 -> 0x1C09C0")

# ---------- 4. 成长分流 stub @0x1C0700 (24B, 数据寄存器比较) ----------
# 判据: a2低字 >= $EA80 (即 $FFEA80+, 敌方槽12+) -> 原版表; 否则增强表
# 调用点实证: 我方 $FFE780~$FFEA3F(槽0-11), 面板 $FF1000/$FF8000, 敌方 $FFEA80+
def side_stub(enh_ptr, orig_ptr):
    s  = "320A"                    # move.w a2,d1      指针低字
    s += "0C41" + "EA80"           # cmpi.w #$EA80,d1
    s += "6408"                    # bhs.s -> offset 16 (敌方)
    s += "47F9" + "%08X" % enh_ptr # lea enh_ptr,a3    我方/面板
    s += "4E75"                    # rts
    s += "47F9" + "%08X" % orig_ptr# enemy: lea orig_ptr,a3
    s += "4E75"                    # rts
    return bytes.fromhex(s)

grow = side_stub(ENH_JUMPTAB, 0x14DAA)
assert len(grow) == 24
# 逐条编码断言(不接受 capstone 渲染差异, 直接锁字节)
assert grow[0:2].hex() == "320a" and grow[2:6].hex() == "0c41ea80"
assert grow[6:8].hex() == "6408"
# bhs 落点 = 敌方 lea 的偏移
assert 8 + int.from_bytes(grow[7:8], 'big') == 16, "bhs 落点错位"

GROW_STUB = 0x1C0700
patch(GROW_STUB, grow, "成长分流stub24B(数据寄存器比较)")
patch(0x14C84, bytes.fromhex("4EB9" + "%08X" % GROW_STUB), "0x14C84 lea->jsr 成长stub")

# ---------- 5. 射程分流 stub @0x1C0740 + 全9表 ----------
rng = side_stub(0x1C0980, 0x14D8C)
assert len(rng) == 24
RNG_STUB = 0x1C0740
patch(RNG_STUB, rng, "射程分流stub24B(数据寄存器比较)")
patch(0x1C0980, b"\x09"*30, "全9射程表30B -> 0x1C0980")
patch(0x14D72, bytes.fromhex("4EB9" + "%08X" % RNG_STUB), "0x14D72 lea->jsr 射程stub")

# ---------- 校验 ----------
assert len(data) == 0x200000
whitelist = [(0x5F08,27),(0x11B20,76),(0x14C84,6),(0x14D72,6),
             (GROW_STUB,24),(RNG_STUB,24),(0x1C0980,30),(0x1C09C0,60),(0x1C0A00,480)]
total = 0
for a,n in whitelist:
    seg_o, seg_n = orig[a:a+n], bytes(data[a:a+n])
    if seg_o == seg_n:
        print("WARN: 区间 0x%06X 无变化?" % a)
    total += sum(1 for x,y in zip(seg_o,seg_n) if x!=y)
mask = bytearray(orig)
for a,n in whitelist:
    mask[a:a+n] = bytes(data[a:a+n])
assert bytes(mask) == bytes(data), "存在白名单外改动!"
for a,n,name in ((0x1536,1920,"出生表"),(PT_PTRS,60,"跳表"),(0x14DE6,480,"参数表"),
                 (0x14D8C,30,"射程表"),(0x6070,6,"伤害A入口"),(0xA38A,6,"伤害C1入口"),
                 (0x5F9C,6,"辅助入口")):
    assert orig[a:a+n] == bytes(data[a:a+n]), name + " 被改动!"
print("白名单改动字节数: %d, 区间数: %d" % (total, len(whitelist)))

print("正式版 MD5: %s" % hashlib.md5(bytes(data)).hexdigest())
out1 = os.path.join(OUT_DIR, "水浒传_简易版_v9.bin")
open(out1,"wb").write(bytes(data))

# ---------- 验证版（ATK init 250） ----------
data2 = bytearray(orig)
for a,n in whitelist:
    data2[a:a+n] = bytes(data[a:a+n])
data2[ENH_PARAMS:ENH_PARAMS+480] = enh_verify
assert len(data2) == 0x200000
print("验证版 MD5: %s" % hashlib.md5(bytes(data2)).hexdigest())
out2 = os.path.join(OUT_DIR, "水浒传_验证版_我方攻击250_v9.bin")
open(out2,"wb").write(bytes(data2))

report = {
    "base_rom_md5": hashlib.md5(orig).hexdigest(),
    "official": {"file": out1, "md5": hashlib.md5(bytes(data)).hexdigest()},
    "verify":   {"file": out2, "md5": hashlib.md5(bytes(data2)).hexdigest()},
    "changed_bytes": total, "regions": len(whitelist),
    "design": "v9: 数据寄存器比较判据 a2低字>=$EA80=敌方; 修复v8的cmpa内存间接bug; 无伤害壳",
    "v8_root_cause": "B5C9=cmpa.l (a1),a2 内存间接; (a1)=$FFEA80处菜单期=0 → 全判敌方 → no-op",
    "detail": [{"addr": "0x%06X"%a, "old": o, "new": nw, "desc": d} for a,o,nw,d in changes]
}
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "v9_report.json"), "w",
     encoding="utf-8").write(json.dumps(report, ensure_ascii=False, indent=1))
print("DONE")
