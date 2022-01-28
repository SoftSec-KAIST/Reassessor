import re
import capstone
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import sys

from asm_types import *
from utils import *
import pickle

RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')


def gen_prog(bin_path):
    elf = load_elf(bin_path)
    cs = get_disassembler(get_arch(elf))
    # Configurate Disassembler
    cs.detail = True
    cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
    prog = Program(elf, cs)
    return prog, elf, cs

def do_comment(line, is_pie):
    if line.startswith('#Procedure'):
        return None
    elif line.startswith('# 0x') and ':' in line:
        addr = int(line[2:].split(':')[0], 16)
        if is_pie:
            addr = addr - 0x400000
        return addr
    elif line.startswith('# data @'):
        addr = int(line[8:], 16)
        if is_pie:
            addr = addr - 0x400000
        return addr
    else:
        print(line)
        print('exit 1')
        #sys.exit(-1)

DATA_DIRECTIVE = ['.byte', '.asciz', '.quad', '.ascii', '.long', '.short']

SKIP_DIRECTIVE = ['.align', '.globl', '.type']

def resolve_addr(lines, i):
    j = i - 1
    while not lines[j][2].endswith(':'):
        j -= 1
    addr = lines[j][1]
    j += 1
    while j != i:
        _, _, line = lines[j]
        if line.startswith('.byte'):
            addr += 1
        elif line.startswith('.quad'):
            addr += 8
        elif line.startswith('.asciz') or line.startswith('.ascii'):
            token = line.split('"')[1]
            addr += len(token) + 1
        elif line.startswith('.long'):
            addr += 4
        elif line.startswith('.short'):
            addr += 2
        else:
            print(line)
            #sys.exit(-1)
        j += 1
    return addr

def trim_lines(src_path, is_pie):
    lines = []
    addr = -1
    assigned = False
    is_linker_gen = False
    with open(src_path) as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if line.startswith('#'):
                addr_ = do_comment(line, is_pie)
                if addr_ is not None:
                    addr = addr_
                    assigned = False
            elif line == '':
                continue
            else:
                token = line.split()[0]
                if token in DATA_DIRECTIVE:
                    if not is_linker_gen:
                        if not assigned:
                            lines.append((idx, addr, line))
                            if line.startswith('.byte'):
                                addr += 1
                            elif line.startswith('.quad'):
                                addr += 8
                            elif line.startswith('.asciz') or line.startswith('.ascii'):
                                token2 = line.split('"')[1]
                                addr += len(token2) + 1
                            elif line.startswith('.long'):
                                addr += 4
                            elif line.startswith('.short'):
                                addr += 2
                            else:
                                print(line)
                            assigned = False
                        else:
                            lines.append((idx, -1, line))
                elif token.endswith(':'):
                    if not is_linker_gen:
                        if not assigned:
                            lines.append((idx, addr, line))
                        else:
                            lines.append((idx, -1, line))
                elif token in SKIP_DIRECTIVE:
                    continue
                elif token == '.section':
                    section = line.split()[1]
                    if section not in ['.fini', '.init', '.plt.got']:
                        is_linker_gen = False
                    else:
                        is_linker_gen = True
                else:
                    if not is_linker_gen:
                        if not assigned:
                            lines.append((idx, addr, line))
                            assigned = False
                        else:
                            print(line, idx)
                            print('exit 2')
                            #sys.exit(-1)
    for i in range(len(lines)):
        idx, addr, line = lines[i]
        if line.endswith(':') and addr == -1:
            addr = resolve_addr(lines, i)
            lines[i] = idx, addr, line
    return lines

def address_labels(lines, addressed_labels):
    addr_ = -1
    addressed_lines = []
    for idx, addr, line in lines[::-1]:
        if line.endswith(':'):
            if addr_ != -1:
                addressed_labels[line.split(':')[0]] = addr_
            else:
                addressed_labels[line.split(':')[0]] = addr
        else:
            addr_ = addr
            addressed_lines.append((idx, addr, line))
    addressed_lines.reverse()
    return addressed_lines

def parse_intel_asm_line(line):
    src_inst = line
    if src_inst.startswith('nop'):
        return []
    if '\t' in src_inst:
        src_inst = src_inst.split('\t', 1)
        src_inst[1] = src_inst[1].split(',')
    else:
        src_inst = [src_inst, []]
    for i in range(len(src_inst[1])):
        src_inst[1][i] = src_inst[1][i].strip()
    return src_inst

def address_src_file(src_path, is_pie, addressed_labels, elf):
    lines = trim_lines(src_path, is_pie)
    addressed_lines = address_labels(lines, addressed_labels)
    addressed_asms = []
    addressed_data = []
    for idx, addr, line in addressed_lines:
        if line.startswith('.'):
            tokens = line.split()
            if tokens[1].startswith('.label') or tokens[1].startswith('label') or tokens[1].startswith('sub'):
                if '+' in tokens[1]:
                    exprs = tokens[1].split('+')
                elif '-' in tokens[1]:
                    exprs = tokens[1].split('-')
                else:
                    exprs = [tokens[1]]
                if tokens[0] == '.quad':
                    addressed_data.append((addr, exprs, 8, idx))
                elif tokens[0] == '.long':
                    addressed_data.append((addr, exprs, 4, idx))
                else:
                    print(line)
                    print('exit 3')
                    #sys.exit(-1)
        else:
            tokens = parse_intel_asm_line(line)
            if len(tokens) > 0:
                addressed_asms.append((addr, tokens, idx))

    return addressed_asms, addressed_data

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

def reduce_expr(s):
    if s.count('[') > 1:
        e = ''
        met_paren = False
        for c in s:
            if not met_paren:
                e += c
                if c == '[' or c == ']':
                    met_paren = True
            else:
                if c == '[' or c == ']':
                    met_paren = False
        return e
    else:
        return s

def tokenize_expr(s):
    tokens = []
    t = ''
    i = -1
    while i < len(s) - 1:
        i += 1
        if i + 2 < len(s) and (s[i:i+3] == ' + ' or s[i:i+3] == ' - '):
            tokens.append(t)
            tokens.append(s[i:i+3])
            i += 2
            t = ''
        else:
            t += s[i]
    tokens.append(t)
    return tokens

def filter_tokens(addressed_labels, tokens):
    tokens_ = []
    i = -1
    while i < len(tokens) - 1:
        i += 1
        if tokens[i] == ' + ' or tokens[i] == ' - ':
            continue
        else:
            if tokens[i] not in addressed_labels:
                i += 1
            else:
                tokens_.append(tokens[i])
    return tokens_

def get_label_expr(addressed_labels, s):
    s = reduce_expr(s)
    digits = "-0123456789"
    if '[' in s:
        s = s.split('[')[1].split(']')[0]
        tokens = tokenize_expr(s)
        tokens = filter_tokens(addressed_labels, tokens)
        return tokens
    elif 'OFFSET FLAT' in s:
        s = s.split('OFFSET FLAT:')[1]
        tokens = tokenize_expr(s)
        tokens = filter_tokens(addressed_labels, tokens)
        return tokens
    else:
        if s[0] in digits:
            return []
        elif s in addressed_labels:
            return [s]
        elif 'sub' in s: # non .text section
            return [s]
        elif '_start' in s: # non .text section
            return [s]
        elif 'label' in s: # undefined label
            return []
        else:
            print(s)
            print('exit 4')
            #sys.exit(-1)

def has_label(addressed_labels, s):
    return s in addressed_labels

def is_gotoff(s):
    return '@GOTOFF' in s

def parse_labels(addressed_labels, value, tokens):
    terms = []
    for token in tokens:
        if token in addressed_labels:
            if addressed_labels[token] == 0:
                v = value
            else:
                v = addressed_labels[token]

            if is_gotoff(token):
                lbl = Label(token, LblTy.GOTOFF, v)
            else:
                lbl = Label(token, LblTy.LABEL, v)
            terms.append(lbl)
        else:
            terms.append(token)
    return terms

def parse_intel_components(addressed_labels, insn, src):
    digits = "-0123456789"
    insn_operands = insn.operands
    result = []
    if len(insn_operands) == 2 and len(src[1]) == 1:
        result.append(Component())
        insn_operands = insn_operands[1:]
    for idx, i in enumerate(insn_operands):
        s = src[1][idx]
        if i.type == X86_OP_REG:
            result.append(Component())
        elif i.type == X86_OP_IMM:
            is_pcrel = False
            if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                is_pcrel = True
            tokens = get_label_expr(addressed_labels, s)
            if len(tokens) > 0:
                value = i.imm
                terms = parse_labels(addressed_labels, value, tokens)
                result.append(Component(terms, value, is_pcrel))
            else:
                result.append(Component())
        elif i.type == X86_OP_MEM:
            tokens = get_label_expr(addressed_labels, s)
            is_pcrel = False
            if len(tokens) > 0:
                if i.mem.base == X86_REG_RIP:
                    value = insn.address + insn.size + i.mem.disp
                    is_pcrel = True
                else:
                    value = i.mem.disp
                terms = parse_labels(addressed_labels, value, tokens)
                result.append(Component(terms, value, is_pcrel))
            else:
                result.append(Component())
    result.reverse()
    return result

def parse_source(prog, elf, cs, src_path):
    print(src_path)
    is_pie = 'nopie' not in src_path
    addressed_labels = get_reloc_symbs(prog, elf)
    addressed_asms, addressed_data = address_src_file(src_path, is_pie, addressed_labels, elf)
    print('address_src_file done')

    for i in range(len(addressed_asms)):
        addr, tokens, line = addressed_asms[i]
        try:
            if i == len(addressed_asms) - 1:
                inst = prog.disasm(cs, addr, 15)
            else:
                next_addr, _, _ = addressed_asms[i+1]
                if addr == next_addr: # XXX
                    continue
                inst = prog.disasm(cs, addr, next_addr - addr)
            components = parse_intel_components(addressed_labels, inst, tokens)
            for c in components:
                lbls = c.get_labels()
                if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                    c.Value += prog.get_got_addr(elf)
            prog.Instrs[addr] = Instr(addr, components, src_path, line)
        except:
            pass

    print('address_asms done')
    for addr, exprs, size, line in addressed_data:
        terms = parse_labels(addressed_labels, 0, exprs)
        component = Component(terms, 0) # Dummy value
        prog.Data[addr] = Data(addr, component, src_path, line)

def main(bin_path, src_path, result_path):
    prog, elf, cs = gen_prog(bin_path)
    parse_source(prog, elf, cs, src_path)
    print('done')
    with open(result_path, 'wb') as f:
        pickle.dump(prog, f)

if __name__ == '__main__':
    src_path = sys.argv[1]
    bin_path = sys.argv[2]
    result_path = sys.argv[3]
    # Assume these parameters are always valid
    main(src_path, bin_path, result_path)
