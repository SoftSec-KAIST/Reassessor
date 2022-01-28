import capstone
from capstone.x86 import *
import sys

from asm_types import *
from utils import *

def get_main(bin_path):
    path = bin_path.replace('stripbin', 'bin')
    elf = load_elf(path)
    symtab = elf.get_section_by_name('.symtab')
    symb = symtab.get_symbol_by_name('main')[0]
    return symb['st_value']

def gen_prog(bin_path):
    main_addr = get_main(bin_path)
    elf = load_elf(bin_path)
    cs = get_disassembler(get_arch(elf))
    # Configurate Disassembler
    cs.detail = True
    cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
    prog = Program(elf, cs)
    return prog, elf, cs, main_addr

def is_text_start(line):
    return line == '.text'

def is_text_end(line):
    return line.startswith('# end section .text')

def is_data_start(line):
    return line == '.data' or \
           line == '.bss' or \
           line.startswith('.section .rodata') or \
           line.startswith('.section .data.rel.ro')

def is_data_end(line):
    if line.startswith('# end section .data'):
        return True
    elif line.startswith('# end section .bss'):
        return True
    elif line.startswith('# end section .rodata'):
        return True
    elif line.startswith('# end section .data.rel.ro'):
        return True
    else:
        return False

def need_text_line(line):
    tokens = line.split()
    token = tokens[0]
    if line.startswith('.'):
        if token[-1] == ':': # Label
            # Ddisasm-defined labels
            if token.startswith('.L_'):
                return True
            else:
                return False
        elif token == '.byte':
            return True
        else:
            return False
    else: # instruction
        if token[-1] == ':':
            if token.startswith('FUN'):
                return True
            if token.startswith('main'):
                return True
            else:
                return False
        else:
            return True

def need_data_line(line):
    if line.startswith('.'):
        token = line.split()[0]
        if token == '.section' or token == '.data' or token == '.bss':
            return False
        elif token == '.globl':
            return False
        elif token == '.type':
            return False
        elif token == '.weak':
            return False
        elif token == '.align':
            return False
        elif token[-1] == ':':
            if token.startswith('.L_'):
                return True
            else:
                print('need_data_line')
                print(line)
                #sys.exit(-1)
        elif token == '.zero':
            return True
        elif token == '.byte':
            return True
        elif token == '.quad':
            return True
        elif token == '.string':
            return True
        elif token == '.long':
            return True
        elif token == '.word':
            return True
        elif token.startswith('.asciz') or token.startswith('.ascii'):
            return True
        else:
            print('need_data_line')
            print(line)
            #sys.exit(-1)

def split_source(src_path):
    text_lines = []
    data_lines = []
    within_text = False
    within_data = False
    with open(src_path) as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if is_text_start(line):
                within_text = True
            elif is_text_end(line):
                within_text = False
            elif is_data_start(line):
                within_data = True
            elif is_data_end(line):
                within_data = False

            if line == '':
                continue
            elif line[0] == '#': # Comment
                continue

            if within_text:
                if need_text_line(line):
                    line = line.split(' #')[0]
                    text_lines.append((idx, line))
            elif within_data:
                if need_data_line(line):
                    line = line.split(' #')[0]
                    data_lines.append((idx, line))
    return text_lines, data_lines

SYM_BLK = ['__rela_iplt_end']

def is_register(relocs, s):
    if '@' in s:
        is_plt = '@PLT' in s
        is_gotpcrel = '@GOTPCREL' in s
        s = s.split('@')[0]
    else:
        is_plt = False
        is_gotpcrel = False
    if s in REGISTERS:
        return True
    elif s.startswith('.L_') or s.startswith('FUN'):
        return False
    elif is_plt:
        return False
    elif is_gotpcrel:
        return False
    elif s in relocs:
        return False
    elif s in SYM_BLK:
        return False
    elif is_const(s):
        return False
    elif s == '_DYNAMIC':
        return False
    elif s == '_GLOBAL_OFFSET_TABLE_':
        return False
    elif s == '_GLOBAL_OFFSET_TABLE_]':
        return False
    else:
        print(s)
        print('is_register')
        #sys.exit(-1)

def get_addr_from_label(main_addr, relocs, line, v):
    if '@' in line:
        is_plt = '@PLT' in line
        is_gotpcrel = '@GOTPCREL' in line
        line = line.split('@')[0]
    else:
        is_plt = False
        is_gotpcrel = False
    if line.startswith('.L_'):
        return int(line[3:], 16)
    elif line.startswith('FUN_'):
        return int(line[4:])
    elif line == 'main':
        return main_addr
    elif is_plt:
        return v
    elif is_gotpcrel:
        return v
    elif line in relocs:
        return relocs[line]
    elif line in SYM_BLK:
        return v
    elif is_const(line):
        return int(line)
    elif line == '_DYNAMIC':
        return v
    elif line == '_GLOBAL_OFFSET_TABLE_':
        return v
    elif line == '_GLOBAL_OFFSET_TABLE_]':
        return v
    else:
        print('get_addr_from_label')
        print(line)
        #sys.exit(-1)

def has_label(line):
    return line.startswith('.L_') or line.startswith('FUN_')

def parse_intel_asm_line(line):
    src_inst = line
    if src_inst.startswith('nop'):
        return []
    if ' ' in src_inst:
        src_inst = src_inst.split(' ', 1)
        if src_inst[0].startswith("rep"):
            s = src_inst[1].split(" ", 1)
            src_inst[0] += " " + s[0]
            if len(s) > 1:
                src_inst[1] = s[1]
            else:
                src_inst[1] = ''
        src_inst[1] = src_inst[1].split(',')
    else:
        src_inst = [src_inst, []]
    for i in range(len(src_inst[1])):
        src_inst[1][i] = src_inst[1][i].strip()
    return src_inst

def is_trailing_nop(lines, i):
    j = i + 1
    while j < len(lines):
        line = lines[j][1]
        if line != 'nop':
            if line[-1] == ':':
                return True
            else:
                return False
        else:
            j += 1

def is_semantically_nop_str(tokens):
    try:
        if len(tokens) == 0:
            return True
        mnemonic = tokens[0]
        if mnemonic.startswith("nop"):
            return True
        if mnemonic.startswith("lea"):
            if len(tokens[1]) == 2:
                return tokens[1][0] == tokens[1][1] or "[" + tokens[1][0] + "]" in tokens[1][1]
            else:
                return False
        elif mnemonic.startswith("mov"):
            if len(tokens[1]) == 2:
                return tokens[1][0] == tokens[1][1]
            else:
                return False
        else:
            return False
    except:
        assert False, 'unexpected instruction ' + str(tokens)
    return False

def address_text_lines(prog, cs, main_addr, relocs, lines):
    ranges = {}
    prev_addr = -1
    for _, line in lines:
        if has_label(line) or line == 'main:':
            addr = get_addr_from_label(main_addr, relocs, line[:-1], 0)
            if prev_addr != -1:
                ranges[prev_addr] = addr
                prev_addr = addr
            else:
                prev_addr = addr
    ranges[prev_addr] = prev_addr - 1

    addressed_asms = []
    ins_off = -1
    instrs = []
    i = -1
    cur_addr = -1
    while i < len(lines) - 1:
        i += 1
        lineno, line = lines[i]
        if has_label(line) or line == 'main:':
            addr = get_addr_from_label(main_addr, relocs, line[:-1], 0)
            next_addr = ranges[addr]
            instrs = prog.disasm_range(cs, addr, next_addr - addr)
            ins_off = 0
            cur_addr = addr
        elif line.startswith('.byte'):
            while i < len(lines) - 1:
                lineno, line = lines[i]
                if has_label(line) or line == 'main:':
                    break
                i += 1
            i -= 1
        else:
            instr = instrs[ins_off]
            #print(line, instr, hex(cur_addr))
            assert (cur_addr == instr.address)
            cur_addr += instr.size
            tokens = parse_intel_asm_line(line)
            if is_semantically_nop_str(tokens) or tokens[0] != instr.mnemonic:
                while i < len(lines) - 1:
                    lineno, line = lines[i]
                    if has_label(line) or line == 'main:':
                            break
                    i += 1
                if i != len(lines) - 1:
                    i -= 1
                continue

            ins_off += 1
            if len(tokens) > 0:
                addressed_asms.append((instr.address, tokens, lineno, instr))
    return addressed_asms

def address_data_lines(relocs, lines):
    addressed_data = []
    addr = -1
    for lineno, line in lines:
        #if '.L_40c7b0:' in line:
        #    import pdb
        #    pdb.set_trace()
        if line.startswith('.L_'):
            addr = get_addr_from_label(0, relocs, line[:-1], 0)
        elif addr == -1:
            continue
        elif line.startswith('.zero'):
            n = int(line.split()[1])
            addr += n
        elif line.startswith('.byte'):
            addr += 1
        elif line.startswith('.string'):
            #s = line.split('"')[1]
            #addr += len(s) + 1
            token = '"'.join(line.split('"')[1:])[:-1]
            addr += len(token) + 1
        elif line.startswith('.quad'):
            expr = line.split()[1]
            if has_label(expr):
                addressed_data.append((addr, expr, 8, lineno))
            addr += 8
        elif line.startswith('.long'):
            expr = line.split()[1]
            if has_label(expr):
                addressed_data.append((addr, expr, 4, lineno))
            addr += 4
        elif line.startswith('.ascii'):
            token = '"'.join(line.split('"')[1:])[:-1]
            addr += len(token)
        elif line.startswith('.asciz'):
            token = '"'.join(line.split('"')[1:])[:-1]
            addr += len(token) + 1

    return addressed_data

def simplify_expr(expr):
    if 'OFFSET ' in expr:
        expr = expr.split('OFFSET ')[1]
    if '[' in expr:
        expr = expr.split('[')[1].split(']')[0]
        return expr
    else:
        return expr

def is_operator(s):
    return s in ['+', '-', '*']

def tokenize_expr(expr):
    t = ''
    tokens = []
    for c in expr:
        if is_operator(c):
            tokens.append(t)
            tokens.append(c)
            t = ''
        else:
            t += c
    tokens.append(t)
    return tokens

def is_const(s):
    decimal = '0123456789'
    for c in s:
        if c not in decimal:
            return False
    return True

REGISTERS = ['RIP', 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
        'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D',
        'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP']

def remove_registers(relocs, tokens):
    tokens_ = []
    for token in tokens:
        if is_operator(token):
            tokens_.append(token)
        elif is_const(token):
            tokens_.append(token)
        elif is_register(relocs, token):
            tokens_.append('0')
        else:
            tokens_.append(token)
    return tokens_

def extract_const_terms(tokens):
    tokens_ = []
    labels = []
    i = -1
    while i < len(tokens) - 1:
        i += 1
        if i % 2 == 1:
            if is_operator(tokens[i]):
                if is_const(tokens[i+1]):
                    tokens_.append(tokens[i])
                    tokens_.append(tokens[i+1])
                    i += 1
                else:
                    if len(labels) > 0:
                        labels.append(tokens[i])
                    labels.append(tokens[i+1])
                    tokens_.append(tokens[i])
                    tokens_.append('0')
                    i += 1
            else:
                print('extract_const_terms')
                #sys.exit(-1)
        else:
            if is_const(tokens[i]):
                tokens_.append(tokens[i])
            else:
                labels.append(tokens[i])
                tokens_.append('0')
    s = ''.join(tokens_)
    if len(s) > 0:
        c = eval(s)
    else:
        c = 0
    return labels, c

def parse_expr(relocs, expr):
    expr = simplify_expr(expr)
    tokens = tokenize_expr(expr)
    tokens = remove_registers(relocs, tokens)
    labels, c = extract_const_terms(tokens)
    return labels, c

def is_gotoff(s):
    return s.endswith('@GOTOFF') or s.endswith("@GOT")

def parse_label(relocs, s, v):
    if is_gotoff(s):
        v = get_addr_from_label(0, relocs, s.split('@GOT')[0], v)
        lbl = Label(s, LblTy.GOTOFF, v)
        return lbl
    else:
        v = get_addr_from_label(0, relocs, s, v)
        lbl = Label(s, LblTy.LABEL, v)
        return lbl

def parse_labels(relocs, labels, v):
    terms = []
    for label in labels:
        lbl = parse_label(relocs, label, v)
        terms.append(lbl)
    return terms

def parse_intel_components(relocs, insn, src):
    operands = insn.operands
    components = []
    if len(operands) == 2 and len(src[1]) == 1:
        operands = operands[:-1]
        components.append(Component())
    elif len(operands) == 2 and len(src[1]) == 0:
        operands = []
        components.append(Component())
        components.append(Component())
    #print(insn, src, operands)
    for idx, operand in enumerate(operands):
        s = src[1][idx]
        if operand.type == X86_OP_REG:
            components.append(Component())
        elif operand.type == X86_OP_MEM:
            labels, c = parse_expr(relocs, s)
            is_pcrel = False
            if len(labels) > 0:
                if operand.mem.base == X86_REG_RIP:
                    value = insn.address + insn.size + operand.mem.disp
                    is_pcrel = True
                else:
                    value = operand.mem.disp
                terms = parse_labels(relocs, labels, value)
                if c != 0:
                    terms.append(c)
                component = Component(terms, value, is_pcrel)
                components.append(component)
            else:
                components.append(Component())
        elif operand.type == X86_OP_IMM:
            is_pcrel = False
            if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                is_pcrel = True
            labels, c = parse_expr(relocs, s)
            if len(labels) > 0:
                value = operand.imm
                terms = parse_labels(relocs, labels, value)
                if c != 0:
                    terms.append(c)
                component = Component(terms, value, is_pcrel)
                components.append(component)
            else:
                components.append(Component())
        else:
            print('parse_intel_components')
            #sys.exit(-1)
    if len(operands) == 2 and len(src[1]) == 1:
        components.append(Component())
    components.reverse()
    return components

def parse_data_component(relocs, expr):
    labels, c = parse_expr(relocs, expr)
    terms = []
    for i in range(len(labels)):
        if i % 2 == 1:
            if is_operator(labels[i]):
                continue
            else:
                print('parse_data_component')
                #sys.exit(-1)
        else:
            if has_label(labels[i]):
                lbl = parse_label(relocs, labels[i], 0)
                terms.append(lbl)
            else:
                print('parse_data_component')
                #sys.exit(-1)
    if c != 0:
        terms.append(c)
    component = Component(terms)
    return component

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

def parse_source(prog, elf, cs, src_path, main_addr):
    print(src_path)
    text_lines, data_lines = split_source(src_path)
    relocs = get_reloc_symbs(prog, elf)
    addressed_asms = address_text_lines(prog, cs, main_addr, relocs, text_lines)
    addressed_data = address_data_lines(relocs, data_lines)
    for addr, tokens, line, insn in addressed_asms:
        components = parse_intel_components(relocs, insn, tokens)
        for c in components:
            lbls = c.get_labels()
            if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                c.Value += prog.get_got_addr(elf)
        prog.Instrs[addr] = Instr(addr, components, src_path, line)
    for addr, expr, size, lineno in addressed_data:
        component = parse_data_component(relocs, expr)
        prog.Data[addr] = Data(addr, component, src_path, lineno)

def main(bin_path, src_path):
    prog, elf, cs, main_addr = gen_prog(bin_path)
    parse_source(prog, elf, cs, src_path, main_addr)
    #sys.exit(-1)

if __name__ == '__main__':
    src_path = sys.argv[1]
    bin_path = sys.argv[2]
    # Assume these parameters are always valid
    main(src_path, bin_path)
