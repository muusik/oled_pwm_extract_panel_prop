#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Johannes Dahl
"""Generate intel_legacy_panel_data.bin from Intel's Windows OLED panel driver.

Based on Chris Xiong's reverse engineering of the driver, described in
https://chrisoft.org/blog/post/2025-04-28.html, and on his gen_panel_prop.py, whose output
format and interpolation formula this follows.

The panel's values are not in this script: they are read from the driver package the user
supplies (PanelDriver.inf and PanelDriver.sys, as in Lenovo's n1fdl04w or n1ndp03w for the
ThinkPad X1 Yoga 1st and 2nd gen). The output is the same as gen_panel_prop.py's.

  - AOR, DELVSS, BrightLevelForACL, ACLCutoffAndDelta: registry values in the .inf.
  - IRC, SP: local arrays of the driver's WriteGammaValueToTcon, initialised by immediate
    stores to its stack frame; the stores are replayed.
  - Interpolation: InterpolateToAllValues computes each of the 101 brightness levels'
    gamma from two of the 32 gamma rows in unrolled code. One pass of its loop body is run
    symbolically, and each level's base row, delta row, multiplier, bias and divisor are
    read off the resulting expressions. Concrete runs of the same code on random gamma
    rows then check them against the formula the kernel uses.

The functions are found through the exception table (.pdata), so no debugging symbols are
needed. Only the x86-64 instructions such compiled code uses are decoded, by
x86_64_decode.py, which has to be next to this script.

Usage: extract_panel_prop.py [-o OUTPUT] SOURCE...
SOURCE is a directory holding PanelDriver.inf and PanelDriver.sys (searched recursively),
those files themselves, or the driver package's .exe (unpacked with innoextract).
"""
import argparse
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # also under python3 -I
sys.dont_write_bytecode = True  # no __pycache__ next to an installed copy
from x86_64_decode import Decoder, Imm, Mem, Reg, Unsupported  # noqa: E402

GAMMA_ROWS = 32
LEVELS = 101
IRC_LEN = 909
SP_LEN = 101


# ---------------------------------------------------------------- PE file

class PE:
    def __init__(self, data):
        self.d = data
        if data[:2] != b"MZ":
            raise Unsupported("not a PE file")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise Unsupported("not a PE file")
        machine, nsec = struct.unpack_from("<HH", data, pe + 4)
        if machine != 0x8664:
            raise Unsupported("not an x86-64 driver")
        optsz = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise Unsupported("not a PE32+ file")
        self.base = struct.unpack_from("<Q", data, opt + 24)[0]
        self.dirs = [struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(16)]
        self.secs = []
        for i in range(nsec):
            o = opt + optsz + 40 * i
            name, vsz, va, rsz, rptr, _, _, _, _, chars = struct.unpack_from("<8sIIIIIIHHI", data, o)
            self.secs.append((name.rstrip(b"\0").decode("latin-1"), va, max(vsz, rsz), rptr, rsz, chars))

    def read(self, rva, n):
        for _, va, size, rptr, rsz, _ in self.secs:
            if va <= rva < va + size:
                o = rva - va
                b = self.d[rptr + o:rptr + min(o + n, rsz)] if o < rsz else b""
                return b + bytes(n - len(b))
        raise Unsupported(f"RVA {rva:#x} outside the image")

    def functions(self):
        """Start RVAs of the functions in the exception table, in executable sections."""
        rva, size = self.dirs[3]
        starts = set()
        for i in range(0, size - size % 12, 12):
            begin, end, _ = struct.unpack_from("<III", self.read(rva + i, 12))
            if any(va <= begin < va + sz and chars & 0x20000000
                   for _, va, sz, _, _, chars in self.secs):
                starts.add(begin)
        return sorted(starts)


# ---------------------------------------------------------------- IRC and SP

def stack_arrays(dec, start, limit=4000):
    """Replay the immediate stores to the stack frame from a function's start up to its
    first branch; return the contiguous byte runs as {(base register, offset): bytes}."""
    mem = {}
    addr = start
    for _ in range(limit):
        ins = dec.decode(addr)
        if ins.op in ("jcc", "jmp", "ret", "int3"):
            break
        if ins.op == "mov" and isinstance(ins.args[1], Imm):
            m = ins.args[0]
            if isinstance(m, Mem) and m.base in (4, 5) and m.index is None:
                v = ins.args[1].v
                for i in range(m.w):
                    mem[(m.base, m.disp + i)] = v >> (8 * i) & 0xFF
        addr = ins.end
    runs = {}
    for base in (4, 5):
        offs = sorted(o for b, o in mem if b == base)
        i = 0
        while i < len(offs):
            j = i
            while j + 1 < len(offs) and offs[j + 1] == offs[j] + 1:
                j += 1
            runs[(base, offs[i])] = bytes(mem[(base, o)] for o in range(offs[i], offs[j] + 1))
            i = j + 1
    return runs


def find_irc_sp(pe, dec):
    found = []
    for f in pe.functions():
        try:
            runs = stack_arrays(dec, f)
        except (Unsupported, IndexError):
            continue
        irc = [r for r in runs.values() if len(r) == IRC_LEN]
        sp = [r for r in runs.values() if len(r) == SP_LEN]
        if len(irc) == 1 and len(sp) == 1:
            found.append((f, irc[0], sp[0]))
    if len(found) != 1:
        raise Unsupported(f"expected one function with IRC and SP tables, found {len(found)}")
    return found[0]


# ---------------------------------------------------------------- Interpolation
#
# Values are ints (concrete, 64-bit unsigned) or Sym: a linear combination of atoms plus a
# constant. Atoms: ("arg", n) pointer arguments, ("g", row) the gamma rows of the loop's
# column, ("q", numerator, divisor) a quotient, ("mulhi", numerator, magic, shift) the high
# half of a multiplication by a division constant, ("unk", ...) anything else.
# Branches and conditional moves on symbolic flags take the path of a positive delta, which
# is where the multiplier, bias and divisor appear in the code.

class Sym:
    __slots__ = ("t", "c")

    def __init__(self, t, c=0):
        self.t = {k: v for k, v in t.items() if v}
        self.c = c

    def key(self):
        return (tuple(sorted(self.t.items(), key=repr)), self.c)

    @staticmethod
    def of_key(k):
        return Sym(dict(k[0]), k[1])


def sym(v):
    return v if isinstance(v, Sym) else Sym({}, v)


def mk(t, c):
    s = Sym(t, c)
    return s if s.t else c


def s_add(a, b, k=1):
    a, b = sym(a), sym(b)
    t = dict(a.t)
    for x, v in b.t.items():
        t[x] = t.get(x, 0) + k * v
    return mk(t, a.c + k * b.c)


def s_mul(a, k):
    a = sym(a)
    return mk({x: v * k for x, v in a.t.items()}, a.c * k)


MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}


def signed(v, w):
    v &= MASK[w]
    return v - (1 << 8 * w) if v >> (8 * w - 1) else v


class Machine:
    def __init__(self, dec):
        self.dec = dec
        self.r = [Sym({("unk", "reg", i): 1}) for i in range(16)]
        for i, n in enumerate((1, 2, 8, 9)):  # rcx, rdx, r8, r9
            self.r[n] = Sym({("arg", i): 1})
        self.r[4] = Sym({("stack",): 1})
        self.mem = {}
        self.stores = []
        self.flags = None  # (ZF, SF, CF, OF), or None while unknown

    def rd(self, a):
        if isinstance(a, Imm):
            return a.v
        if isinstance(a, Reg):
            v = self.r[a.n]
            if isinstance(v, Sym):
                return v
            return (v >> 8 & 0xFF) if a.hi else v & MASK[a.w]
        addr = self.ea(a)
        k = sym(addr).key() + (a.w,)
        if k in self.mem:
            return self.mem[k]
        return Sym({("load", sym(addr).key(), a.w): 1})

    def ea(self, m):
        v = m.disp
        if m.base is not None:
            v = s_add(v, self.r[m.base])
        if m.index is not None:
            iv = self.r[m.index]
            v = s_add(v, s_mul(iv, m.scale) if isinstance(iv, Sym) else iv * m.scale)
        return v if isinstance(v, Sym) else v & MASK[8]

    def wr(self, a, v):
        if isinstance(a, Reg):
            old = self.r[a.n]
            if isinstance(v, Sym):
                self.r[a.n] = v
            elif a.w == 8 or a.w == 4:
                self.r[a.n] = v & MASK[a.w]
            elif isinstance(old, Sym):
                self.r[a.n] = Sym({("unk", "partial", id(a)): 1})
            elif a.hi:
                self.r[a.n] = old & ~0xFF00 | (v & 0xFF) << 8
            else:
                self.r[a.n] = old & ~MASK[a.w] | v & MASK[a.w]
            return
        addr = self.ea(a)
        if not isinstance(v, Sym):
            v &= MASK[a.w]
        self.mem[sym(addr).key() + (a.w,)] = v
        self.stores.append((addr, a.w, v))

    def setflags(self, res, w, cf=0, of=0):
        if isinstance(res, Sym):
            self.flags = (0, 0, 0, 0)  # assumed positive and non-zero
        else:
            self.flags = (int(res & MASK[w] == 0), res >> (8 * w - 1) & 1, cf, of)

    def cond(self, cc):
        if self.flags is None:
            raise Unsupported("condition on unknown flags")
        zf, sf, cf, of = self.flags
        c = (of, cf, zf, cf | zf, sf, 0, sf != of, zf or sf != of)[cc >> 1]
        return bool(c) != bool(cc & 1)

    def run(self, start, limit=20000):
        """Run from start until a backward branch, a call or a return."""
        addr = start
        for _ in range(limit):
            ins = self.dec.decode(addr)
            nxt = self.step(ins)
            if nxt is None:
                return
            if nxt <= ins.addr:
                return
            addr = nxt
        raise Unsupported("no end found")

    def step(self, ins):
        op, a = ins.op, ins.args
        w = a[0].w if a and not isinstance(a[0], Imm) else 8
        if op == "nop":
            pass
        elif op == "mov":
            self.wr(a[0], self.rd(a[1]))
        elif op == "movzx":
            self.wr(a[0], self.rd(a[1]))
        elif op == "movsx":
            v = self.rd(a[1])
            self.wr(a[0], v if isinstance(v, Sym) else signed(v, a[1].w))
        elif op == "lea":
            self.wr(a[0], self.ea(a[1]))
        elif op in ("add", "sub", "cmp"):
            x, y = self.rd(a[0]), self.rd(a[1])
            if isinstance(a[1], Imm):
                y = signed(y, min(w, 4)) if w > 1 else y
            if isinstance(x, Sym) or isinstance(y, Sym):
                res = s_add(x, y, 1 if op == "add" else -1)
                self.setflags(res, w)
            else:
                x, y = x & MASK[w], y & MASK[w]
                if op == "add":
                    res = x + y
                    sx, sy, sr = signed(x, w), signed(y, w), signed(res, w)
                    self.setflags(res, w, int(res > MASK[w]), int((sx < 0) == (sy < 0) != (sr < 0)))
                else:
                    res = x - y
                    sr = signed(x, w) - signed(y, w)
                    self.setflags(res, w, int(x < y), int(not -(1 << (8 * w - 1)) <= sr < 1 << (8 * w - 1)))
            if op != "cmp":
                self.wr(a[0], res)
        elif op in ("and", "or", "xor", "test"):
            if op == "xor" and isinstance(a[1], Reg) and isinstance(a[0], Reg) and a[0].n == a[1].n:
                x = y = 0
            else:
                x, y = self.rd(a[0]), self.rd(a[1])
            if isinstance(x, Sym) or isinstance(y, Sym):
                if op in ("and", "test") and 0 in (x, y):
                    res = 0
                elif op in ("or", "xor") and 0 in (x, y):
                    res = y if x == 0 else x
                elif op == "test" and x is y:
                    res = x
                else:
                    raise Unsupported(f"{op} on a symbolic value at {ins.addr:#x}")
            else:
                if isinstance(a[1], Imm) and w > 1:
                    y = signed(y, min(w, 4))
                res = {"and": x & y, "test": x & y, "or": x | y, "xor": x ^ y}[op] & MASK[w]
            self.setflags(res, w)
            if op != "test":
                self.wr(a[0], res)
        elif op == "neg":
            x = self.rd(a[0])
            res = s_mul(x, -1) if isinstance(x, Sym) else -x & MASK[w]
            self.setflags(res, w, int(x != 0))
            self.wr(a[0], res)
        elif op in ("shl", "shr", "sar"):
            x, k = self.rd(a[0]), self.rd(a[1]) & (63 if w == 8 else 31)
            if not isinstance(x, Sym):
                res = {"shl": x << k, "shr": (x & MASK[w]) >> k, "sar": signed(x, w) >> k}[op] & MASK[w]
            elif op == "shl":
                res = s_mul(x, 1 << k)
            elif op == "shr" and k == 8 * w - 1:
                res = 0  # the sign bit of a value assumed positive
            elif op == "sar" and len(x.t) == 1 and not x.c and next(iter(x.t))[0] == "mulhi" \
                    and next(iter(x.t.values())) == 1:
                at = next(iter(x.t))
                res = Sym({(at[0], at[1], at[2], at[3] + k): 1})
            elif op == "sar":
                res = Sym({("q", x.key(), 1 << k): 1})
            else:
                raise Unsupported(f"{op} on a symbolic value at {ins.addr:#x}")
            self.setflags(res, w)
            self.wr(a[0], res)
        elif op == "imul1":
            if w != 4:
                raise Unsupported(f"imul of width {w} at {ins.addr:#x}")
            x, y = self.rd(Reg(0, 4)), self.rd(a[0])
            if isinstance(x, Sym) and isinstance(y, Sym):
                raise Unsupported(f"product of two symbolic values at {ins.addr:#x}")
            if isinstance(x, Sym) or isinstance(y, Sym):
                s, magic = (x, y) if isinstance(x, Sym) else (y, x)
                self.r[2] = Sym({("mulhi", s.key(), magic, 0): 1})
                self.r[0] = Sym({("unk", "mul-low", ins.addr): 1})
            else:
                p = signed(x, 4) * signed(y, 4)
                self.r[0], self.r[2] = p & MASK[4], p >> 32 & MASK[4]
            self.flags = None
        elif op in ("imul2", "imul3"):
            x = self.rd(a[1])
            y = self.rd(a[0]) if op == "imul2" else signed(self.rd(a[2]), min(w, 4))
            if isinstance(x, Sym) and isinstance(y, Sym):
                raise Unsupported(f"product of two symbolic values at {ins.addr:#x}")
            if isinstance(x, Sym) or isinstance(y, Sym):
                s, k = (x, y) if isinstance(x, Sym) else (y, x)
                res = s_mul(s, signed(k, w))
            else:
                res = signed(x, w) * signed(y, w) & MASK[w]
            self.flags = None
            self.wr(a[0], res)
        elif op == "cwd":  # cwd/cdq/cqo
            x = self.rd(Reg(0, w))
            self.wr(Reg(2, w), 0 if isinstance(x, Sym) else MASK[w] if signed(x, w) < 0 else 0)
        elif op == "cbw":  # cbw/cwde/cdqe
            x = self.rd(Reg(0, w // 2))
            self.wr(Reg(0, w), x if isinstance(x, Sym) else signed(x, w // 2) & MASK[w])
        elif op == "cmov":
            if self.cond(ins.cc):
                self.wr(a[0], self.rd(a[1]))
            elif w == 4 and not isinstance(self.r[a[0].n], Sym):
                self.r[a[0].n] &= MASK[4]
        elif op == "setcc":
            self.wr(a[0], int(self.cond(ins.cc)))
        elif op == "push":
            self.r[4] = s_add(self.r[4], -8)
            self.wr(Mem(4, None, 1, 0, 8), self.rd(a[0]))
        elif op == "pop":
            self.wr(a[0], self.rd(Mem(4, None, 1, 0, 8)))
            self.r[4] = s_add(self.r[4], 8)
        elif op == "jcc":
            return a[0].v if self.cond(ins.cc) else ins.end
        elif op == "jmp":
            if not isinstance(a[0], Imm):
                return None
            return a[0].v
        elif op in ("ret", "call", "int3"):
            return None
        else:
            raise Unsupported(f"{op} at {ins.addr:#x}")
        return ins.end


def divisor(magic, shift):
    a = round(2 ** (32 + shift) / magic)
    if a < 2 or -(-2 ** (32 + shift) // a) != magic:
        raise Unsupported(f"{magic:#x} >> {shift} is no division constant")
    return a


def normalize(v):
    """Turn mulhi atoms into quotients."""
    if not isinstance(v, Sym):
        return v
    t = {}
    for at, k in v.t.items():
        if at[0] == "mulhi":
            at = ("q", at[1], divisor(at[2], at[3]))
        t[at] = t.get(at, 0) + k
    return Sym(t, v.c)


def interpolation_from(dec, start):
    m = Machine(dec)
    m.run(start)
    by_ptr = {}
    for addr, w, v in m.stores:
        if w == 2 and isinstance(addr, Sym) and len(addr.t) == 1:
            (at, k), = addr.t.items()
            if at[0] == "arg" and k == 1:
                by_ptr.setdefault(at, []).append((addr.c, normalize(v)))
    for ptr, stores in by_ptr.items():
        if len(stores) != LEVELS:
            continue
        stores.sort()
        first = stores[0][0]
        if [d for d, _ in stores] != [first + 0x42 * i for i in range(LEVELS)]:
            continue
        return [parse_level(v) for _, v in stores]
    raise Unsupported("no 101 interpolated levels stored")


def gamma_row(at):
    """Row of a load from the gamma table (a pointer argument, 33 words per row)."""
    if at[0] != "load" or at[2] != 2:
        return None
    addr = Sym.of_key(at[1])
    if len(addr.t) != 1 or addr.c % 0x42 or not 0 <= addr.c // 0x42 < GAMMA_ROWS:
        return None
    (p, k), = addr.t.items()
    if p[0] != "arg" or k != 1:
        return None
    return addr.c // 0x42


def parse_level(v):
    """base + (m * (g[d] - g[d + 1]) + bias) / a  ->  (base, d, m, bias, a)"""
    v = sym(v)
    rows = {gamma_row(at): k for at, k in v.t.items() if at[0] == "load"}
    quots = [(at, k) for at, k in v.t.items() if at[0] == "q"]
    if None in rows or v.c or len(rows) != 1 or list(rows.values()) != [1] \
            or len(rows) + len(quots) != len(v.t) or len(quots) > 1:
        raise Unsupported("unexpected shape of a level")
    base = next(iter(rows))
    if not quots:
        return base, max(base - 1, 0), 0, 0, 1
    (at, k), = quots
    num, a = Sym.of_key(at[1]), at[2]
    nrows = {gamma_row(x): c for x, c in num.t.items()}
    if k != 1 or None in nrows or len(nrows) != 2:
        raise Unsupported("unexpected shape of a level's delta")
    d = min(nrows)
    mult = nrows[d]
    if nrows.get(d + 1) != -mult or mult <= 0:
        raise Unsupported("unexpected shape of a level's delta")
    return base, d, mult, num.c, a


def find_interpolation(pe, dec):
    found = []
    for f in pe.functions():
        try:
            found.append((f, interpolation_from(dec, f)))
        except (Unsupported, IndexError, KeyError, ZeroDivisionError):
            continue
    if len(found) != 1:
        raise Unsupported(f"expected one interpolating function, found {len(found)}")
    return found[0]


def check_interpolation(dec, start, interp, trials=200):
    """Run the driver's code on concrete gamma rows, negative deltas included, and compare
    it with the formula the kernel uses on the extracted values."""
    rng = random.Random(0)
    for trial in range(trials):
        g = [rng.randrange(0, 1024) for _ in range(GAMMA_ROWS)]
        if trial % 2:
            g.sort(reverse=True)
        m = Machine(dec)
        for r in range(GAMMA_ROWS):
            m.mem[Sym({("arg", 1): 1}, 0x42 * r).key() + (2,)] = g[r]
        m.run(start)
        out = {a.c: v for a, w, v in m.stores
               if w == 2 and isinstance(a, Sym) and set(a.t) == {("arg", 0)}}
        first = min(out)
        for e, (base, d, mult, bias, att) in enumerate(interp):
            dv = g[d] - g[d + 1]
            q = (abs(dv * mult) + bias) // att
            want = (g[base] + (q if dv > 0 else -q if dv < 0 else 0)) & 0xFFFF
            if out.get(first + 0x42 * e) != want:
                raise Unsupported(f"level {e}: extracted values do not reproduce the driver")


# ---------------------------------------------------------------- .inf

def inf_values(text):
    """Values under HKLM\\SOFTWARE\\Intel\\IGFX in AddReg lines: bytes or int."""
    out = {}
    text = re.sub(r"\\[ \t]*\r?\n", "", text)
    for line in text.splitlines():
        parts, cur, quoted = [], "", False
        for ch in line:
            if ch == '"':
                quoted = not quoted
            elif ch == ";" and not quoted:
                break
            elif ch == "," and not quoted:
                parts.append(cur.strip())
                cur = ""
                continue
            cur += ch
        parts.append(cur.strip())
        if len(parts) < 5 or parts[0].upper() not in ("HKLM", "HKEY_LOCAL_MACHINE"):
            continue
        if parts[1].strip('"').lower() != r"software\intel\igfx":
            continue
        name, flags = parts[2].strip('"'), int(parts[3], 0)
        vals = [x for x in parts[4:] if x]
        if flags & 0xFFFF0001 == 0x00010001:  # REG_DWORD
            x = vals[0]
            out[name] = int(x, 16) if x.lower().startswith("0x") else int(x)
        elif flags & 0xFFFF0001 == 0x00000001:  # REG_BINARY
            out[name] = bytes(int(x, 16) for x in vals)
    return out


def read_text(path):
    b = open(path, "rb").read()
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16")
    return b.decode("latin-1")


# ---------------------------------------------------------------- main

def find_files(sources, tmp):
    inf = sys_ = None
    for s in sources:
        paths = []
        if os.path.isdir(s):
            for root, _, files in os.walk(s):
                paths += [os.path.join(root, f) for f in files]
        elif s.lower().endswith(".exe"):
            if not shutil.which("innoextract"):
                sys.exit(f"{s}: innoextract is needed to unpack it (or pass the unpacked directory)")
            d = tempfile.mkdtemp(dir=tmp)
            subprocess.run(["innoextract", "-s", "-d", d, s], check=True)
            return find_files([d], tmp)
        else:  # a file named on the command line counts by its extension
            n = s.lower()
            if n.endswith(".inf"):
                inf = s
            elif n.endswith(".sys"):
                sys_ = s
            else:
                sys.exit(f"{s}: neither an .inf, a .sys, an .exe nor a directory")
        for p in paths:
            n = os.path.basename(p).lower()
            if n == "paneldriver.inf":
                inf = p
            elif n == "paneldriver.sys":
                sys_ = p
    if not inf or not sys_:
        sys.exit("PanelDriver.inf and PanelDriver.sys not found")
    return inf, sys_


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-o", "--output", default="intel_legacy_panel_data.bin")
    ap.add_argument("source", nargs="+", help="driver package .exe, its unpacked directory, "
                    "or PanelDriver.inf and PanelDriver.sys")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        inf, sysf = find_files(args.source, tmp)
        regs = inf_values(read_text(inf))
        drv = open(sysf, "rb").read()

    for name in ("AOR", "DELVSS", "BrightLevelForACL", "ACLCutoffAndDelta"):
        if name not in regs:
            sys.exit(f"{inf}: no {name}")
    aor, delvss, acl, acl_cd = regs["AOR"], regs["DELVSS"], regs["BrightLevelForACL"], regs["ACLCutoffAndDelta"]
    if len(aor) != 202 or len(delvss) != 101 or not 0 <= acl <= 100 \
            or not (100 - acl) * 2 <= len(acl_cd) <= 200:
        sys.exit(f"{inf}: unexpected lengths of AOR, DELVSS or ACLCutoffAndDelta")

    try:
        pe = PE(drv)
        dec = Decoder(pe.read)
        f1, irc, sp = find_irc_sp(pe, dec)
        f2, interp = find_interpolation(pe, dec)
        check_interpolation(dec, f2, interp)
    except Unsupported as e:
        sys.exit(f"{sysf}: {e}")
    for base, d, mult, bias, a in interp:
        if not (0 <= base <= 31 and 0 <= d <= 30 and 0 <= mult <= 255 and 0 <= bias <= 255
                and 1 <= a <= 255):
            sys.exit(f"{sysf}: interpolation value out of range")

    out = bytearray()
    for t in (aor, delvss):
        out += len(t).to_bytes(2, "little") + t
    out += acl.to_bytes(2, "little")
    for t in (acl_cd, irc, sp):
        out += len(t).to_bytes(2, "little") + t
    out += (LEVELS * 5).to_bytes(2, "little")
    for row in interp:
        out += bytes(row)
    with open(args.output, "wb") as f:
        f.write(out)
    print(f"{args.output}: {len(out)} bytes (IRC and SP from {f1:#x}, interpolation from {f2:#x})")


if __name__ == "__main__":
    main()
