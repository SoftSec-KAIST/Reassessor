import re
import capstone
from capstone.x86 import *
import sys
import os

from asm_types import *
from parser import *
from utils import *

# FIXME: clean up later
RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')

def has_non_digits(s):
    digits = "0123456789+-"
    for c in s:
        if c not in digits:
            return True
    return False

def get_label_expr(s):
    digits = "-0123456789"
    if s == "*":
        # e.g. *(%rsp)
        return None
    elif s[0] == "%":
        # e.g. %fs:40
        return None
    elif s[0] in digits:
        if has_non_digits(s):
            return s
        return None
    elif s[0] in "$*":
        if s[1] in digits:
            return None
        else:
            return s[1:]
    else:
        return s

def is_gotoff(s):
    return '@GOTOFF' in s

# RetroWrite-specific
def parse_label(s, v, relocs):
    if is_gotoff(s):
        print('RetroWrite cannot support x86')
        print(s)
        #sys.exit(-1)
    else:
        if s in relocs:
            v = relocs[s]
            return Label(s, LblTy.LABEL, v)
        elif s.startswith('.LC'):
            v = int(s[3:], 16)
            return Label(s, LblTy.LABEL, v)
        elif s.startswith('.L'):
            v = int(s[2:], 16)
            return Label(s, LblTy.LABEL, v)
        else:
            return Label(s, LblTy.LABEL, v)

# RetroWrite-specific
def has_label(s, relocs):
    if s:
        return ('.L' in s) or ('@' in s) or (s in relocs)
    else:
        return False

def get_const_term(tokens, relocs):
    expr = ''
    for token in tokens:
        if has_label(token, relocs):
            expr += '0'
        else:
            expr += token
    return eval(expr)

def is_operator(c):
    return c == '+' or c == '-'

def reduce_const_term(tokens, relocs):
    const = get_const_term(tokens, relocs)
    tokens_ = []
    i = 0
    while i < len(tokens):
        if has_label(tokens[i], relocs):
            tokens_.append(tokens[i])
        i += 1
    return tokens_, const

def parse_expr(s, v, relocs):
    token = ''
    tokens = []
    # Parsing
    for c in s:
        if is_operator(c):
            if len(token) > 0:
                tokens.append(token)
            tokens.append(c)
            token = ''
        else:
            token += c
    tokens.append(token)

    tokens, const = reduce_const_term(tokens, relocs)
    terms = []

    for token in tokens:
        if not is_operator(token):
            lbl = parse_label(token, v, relocs)
            terms.append(lbl)

    if const != 0:
        terms.append(const)

    return terms

def address_src_file(src_path):
    with open(src_path) as f:
        addressed_asms = []
        addressed_data = []
        addr = -1
        for idx, line in enumerate(f):
            line = line.rstrip()
            if line.startswith('.L') and line.endswith(':'):
                line = line.split(':')[0]
                if line.startswith('.LC'):
                    addr = int(line[3:], 16)
                elif line.startswith('.L'):
                    addr = int(line[2:], 16)
            elif RE_INST.match(line):
                tokens = parse_att_asm_line(line)
                if len(tokens) > 0:
                    addressed_asms.append((addr, tokens, idx))
            elif line.strip().startswith('.long'):
                token = line.split('.long')[1]
                addressed_data.append((addr, token, 4, idx))
            elif line.strip().startswith('.quad'):
                token = line.split('.quad')[1]
                addressed_data.append((addr, token, 8, idx))

    return addressed_asms, addressed_data

def gen_prog(bin_path):
    elf = load_elf(bin_path)
    cs = get_disassembler(get_arch(elf))
    # Configurate Disassembler
    cs.detail = True
    cs.syntax = capstone.CS_OPT_SYNTAX_ATT
    prog = Program(elf, cs)
    return prog, elf, cs

def get_reloc_symbs(prog, elf):
    names = {}

    dynsym = elf.get_section_by_name('.dynsym')
    for symb in dynsym.iter_symbols():
        if symb['st_shndx'] != 'SHN_UNDEF':
            addr = symb['st_value']
            name = symb.name
            if addr != 0:
                names[name] = addr
        else:
            name = symb.name
            addr = symb['st_value']
            if addr != 0:
                names[name] = addr

    return names

def parse_source(prog, elf, cs, src_path):
    #print(src_path)
    addressed_asms, addressed_data = address_src_file(src_path)

    relocs = get_reloc_symbs(prog, elf)

    for i in range(len(addressed_asms)):
        addr, tokens, line = addressed_asms[i]
        if i == len(addressed_asms) - 1:
            inst = prog.disasm(cs, addr, 15)
        else:
            next_addr, _, _ = addressed_asms[i+1]
            inst = prog.disasm(cs, addr, next_addr - addr)
        components = parse_att_components(has_label, get_label_expr, parse_expr, inst, tokens, relocs)
        for c in components:
            lbls = c.get_labels()
            if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                c.Value += prog.get_got_addr(elf)
        prog.Instrs[addr] = Instr(addr, components, src_path, line)
        #print('Inst:', hex(addr))

    for addr, token, size, line in addressed_data:
        terms = parse_expr(token.strip(), 0, relocs)
        component = Component(terms)
        prog.Data[addr] = Data(addr, component, src_path, line)
        #print('Data:', hex(addr))

def main(src_path, bin_path):
    prog, elf, cs = gen_prog(bin_path)
    parse_source(prog, elf, cs, src_path)

if __name__ == '__main__':
    src_path = sys.argv[1]
    bin_path = sys.argv[2]
    # Assume these parameters are always valid
    instrs = main(src_path, bin_path)
