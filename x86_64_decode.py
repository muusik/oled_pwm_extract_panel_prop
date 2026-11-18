# SPDX-License-Identifier: MIT
# Copyright 2026 Johannes Dahl
"""A small x86-64 instruction decoder for extract_panel_prop.py.

It decodes only the general-purpose integer instructions that compiled driver code like
PanelDriver.sys uses (no SSE/AVX, no x87, no string instructions), into Ins records whose
operands are Reg, Mem and Imm. Anything else raises Unsupported. The interface is kept
small so that an external disassembler could take its place: a Decoder is built from a
read(address, length) -> bytes function and decode(address) returns one Ins.

  Ins.op     mnemonic; grouped forms are told apart by name: imul1 (one operand, edx:eax),
             imul2 (two), imul3 (with an immediate); cbw and cwd stand for every width.
  Ins.args   operands, destination first; branch targets are absolute addresses as Imm.
  Ins.cc     condition code (0-15) of jcc, cmov and setcc.
  Reg        register number n (0 rax ... 15 r15), width w in bytes, hi for ah/ch/dh/bh.
  Mem        base and index register numbers (or None), scale, disp, width w; a RIP-relative
             operand has base None and its absolute address as disp.
  Imm        value v: an immediate as encoded (callers mask it to the operand's width) or
             a branch target.
"""

class Unsupported(Exception):
    pass


ALU = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}
GRP3 = {0: "test", 2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div", 7: "idiv"}


class Reg:
    __slots__ = ("n", "w", "hi")

    def __init__(self, n, w, hi=False):
        self.n, self.w, self.hi = n, w, hi


class Mem:
    __slots__ = ("base", "index", "scale", "disp", "w")

    def __init__(self, base, index, scale, disp, w):
        self.base, self.index, self.scale, self.disp, self.w = base, index, scale, disp, w


class Imm:
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v


class Ins:
    __slots__ = ("addr", "end", "op", "args", "cc")

    def __init__(self, addr, end, op, args, cc=None):
        self.addr, self.end, self.op, self.args, self.cc = addr, end, op, args, cc


class Decoder:
    def __init__(self, read):
        self.read = read

    def decode(self, addr):
        b = self.read(addr, 16)
        p = 0
        opsz16 = False
        while b[p] in (0x66, 0xF2, 0xF3, 0x2E, 0x3E):
            opsz16 |= b[p] == 0x66
            p += 1
        rex = 0
        if 0x40 <= b[p] <= 0x4F:
            rex = b[p]
            p += 1
        W, R, X, B = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
        osz = 8 if W else 2 if opsz16 else 4

        def imm(n, signed=True):
            nonlocal p
            v = int.from_bytes(b[p:p + n], "little", signed=signed)
            p += n
            return v

        def reg(n, w):
            if w == 1 and not rex and 4 <= n <= 7:
                return Reg(n - 4, 1, True)
            return Reg(n, w)

        def modrm(w, regw=None):
            nonlocal p
            m = b[p]
            p += 1
            mod, r, rm = m >> 6, (m >> 3 & 7) | R << 3, m & 7
            if mod == 3:
                return r, reg(rm | B << 3, w)
            index, scale, base = None, 1, None
            if rm == 4:
                sib = b[p]
                p += 1
                scale = 1 << (sib >> 6)
                i = (sib >> 3 & 7) | X << 3
                index = None if i == 4 else i
                if sib & 7 == 5 and mod == 0:
                    disp = imm(4)
                else:
                    base = (sib & 7) | B << 3
                    disp = 0
            elif rm == 5 and mod == 0:
                base = "rip"
                disp = imm(4)
            else:
                base = rm | B << 3
                disp = 0
            if mod == 1:
                disp = imm(1)
            elif mod == 2:
                disp = imm(4)
            return r, Mem(base, index, scale, disp, w)

        def done(op, args, cc=None):
            end = addr + p
            for a in args:
                if isinstance(a, Mem) and a.base == "rip":
                    a.base, a.disp = None, end + a.disp
            return Ins(addr, end, op, args, cc)

        o = b[p]
        p += 1
        if o < 0x40 and o & 7 < 6 and o not in (0x26, 0x2E, 0x36, 0x3E):
            op, form = ALU[o >> 3], o & 7
            w = 1 if form in (0, 2, 4) else osz
            if form in (0, 1):
                r, rm = modrm(w)
                return done(op, [rm, reg(r, w)])
            if form in (2, 3):
                r, rm = modrm(w)
                return done(op, [reg(r, w), rm])
            return done(op, [Reg(0, w), Imm(imm(1 if w == 1 else min(w, 4)))])
        if 0x50 <= o <= 0x57:
            return done("push", [Reg(o - 0x50 | B << 3, 8)])
        if 0x58 <= o <= 0x5F:
            return done("pop", [Reg(o - 0x58 | B << 3, 8)])
        if o == 0x63:
            r, rm = modrm(4)
            return done("movsx", [reg(r, osz), rm])
        if o in (0x69, 0x6B):
            r, rm = modrm(osz)
            return done("imul3", [reg(r, osz), rm, Imm(imm(1 if o == 0x6B else min(osz, 4)))])
        if 0x70 <= o <= 0x7F:
            rel = imm(1)
            return done("jcc", [Imm(addr + p + rel)], o & 15)
        if o in (0x80, 0x81, 0x83):
            w = 1 if o == 0x80 else osz
            r, rm = modrm(w)
            return done(ALU[r & 7], [rm, Imm(imm(4 if o == 0x81 and w > 2 else 2 if o == 0x81 else 1))])
        if o in (0x84, 0x85):
            w = 1 if o == 0x84 else osz
            r, rm = modrm(w)
            return done("test", [rm, reg(r, w)])
        if 0x88 <= o <= 0x8B:
            w = 1 if o in (0x88, 0x8A) else osz
            r, rm = modrm(w)
            return done("mov", [rm, reg(r, w)] if o < 0x8A else [reg(r, w), rm])
        if o == 0x8D:
            r, rm = modrm(osz)
            return done("lea", [reg(r, osz), rm])
        if o == 0x90:
            return done("nop", [])
        if o == 0x98:
            return done("cbw", [Reg(0, osz)])
        if o == 0x99:
            return done("cwd", [Reg(0, osz)])
        if o in (0xA8, 0xA9):
            w = 1 if o == 0xA8 else osz
            return done("test", [Reg(0, w), Imm(imm(1 if w == 1 else min(w, 4)))])
        if 0xB0 <= o <= 0xB7:
            return done("mov", [reg(o - 0xB0 | B << 3, 1), Imm(imm(1, False))])
        if 0xB8 <= o <= 0xBF:
            return done("mov", [Reg(o - 0xB8 | B << 3, osz), Imm(imm(osz, False))])
        if o in (0xC0, 0xC1, 0xD0, 0xD1):
            w = 1 if o in (0xC0, 0xD0) else osz
            r, rm = modrm(w)
            if r & 7 not in SHIFTS:
                raise Unsupported(f"shift group /{r & 7} at {addr:#x}")
            return done(SHIFTS[r & 7], [rm, Imm(imm(1, False) if o < 0xD0 else 1)])
        if o in (0xC2, 0xC3):
            return done("ret", [])
        if o in (0xC6, 0xC7):
            w = 1 if o == 0xC6 else osz
            r, rm = modrm(w)
            if r & 7:
                raise Unsupported(f"C6/C7 /{r & 7} at {addr:#x}")
            return done("mov", [rm, Imm(imm(1 if w == 1 else min(w, 4)))])
        if o == 0xCC:
            return done("int3", [])
        if o == 0xE8:
            rel = imm(4)
            return done("call", [Imm(addr + p + rel)])
        if o in (0xE9, 0xEB):
            rel = imm(4 if o == 0xE9 else 1)
            return done("jmp", [Imm(addr + p + rel)])
        if o in (0xF6, 0xF7):
            w = 1 if o == 0xF6 else osz
            r, rm = modrm(w)
            if r & 7 not in GRP3:
                raise Unsupported(f"group 3 /{r & 7} at {addr:#x}")
            op = GRP3[r & 7]
            if op == "test":
                return done(op, [rm, Imm(imm(1 if w == 1 else min(w, 4)))])
            return done(op, [rm])
        if o in (0xFE, 0xFF):
            r, rm = modrm(1 if o == 0xFE else 8 if (b[p] >> 3 & 7) in (2, 4, 6) else osz)
            op = {0: "inc", 1: "dec", 2: "call", 4: "jmp", 6: "push"}.get(r & 7)
            if op is None:
                raise Unsupported(f"FE/FF /{r & 7} at {addr:#x}")
            return done(op, [rm])
        if o == 0x0F:
            o2 = b[p]
            p += 1
            if o2 == 0x1F:
                modrm(osz)
                return done("nop", [])
            if 0x40 <= o2 <= 0x4F:
                r, rm = modrm(osz)
                return done("cmov", [reg(r, osz), rm], o2 & 15)
            if 0x80 <= o2 <= 0x8F:
                rel = imm(4)
                return done("jcc", [Imm(addr + p + rel)], o2 & 15)
            if 0x90 <= o2 <= 0x9F:
                _, rm = modrm(1)
                return done("setcc", [rm], o2 & 15)
            if o2 == 0xA3:
                r, rm = modrm(osz)
                return done("bt", [rm, reg(r, osz)])
            if o2 == 0xAF:
                r, rm = modrm(osz)
                return done("imul2", [reg(r, osz), rm])
            if o2 in (0xB6, 0xB7, 0xBE, 0xBF):
                sw = 1 if o2 in (0xB6, 0xBE) else 2
                r, rm = modrm(sw)
                return done("movzx" if o2 < 0xBE else "movsx", [reg(r, osz), rm])
            if o2 == 0xBA:
                r, rm = modrm(osz)
                if r & 7 != 4:
                    raise Unsupported(f"0F BA /{r & 7} at {addr:#x}")
                return done("bt", [rm, Imm(imm(1, False))])
            raise Unsupported(f"opcode 0F {o2:02X} at {addr:#x}")
        raise Unsupported(f"opcode {o:02X} at {addr:#x}")
