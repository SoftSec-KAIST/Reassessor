import re
import capstone
from capstone.x86 import *
import sys
import os
import pickle

from lib.asm_types import *
#from lib.parser import *
from lib.utils import *
import glob, json
from elftools.elf.descriptions import describe_reloc_type
from mapper.match_src_to_bin import get_dwarf_loc, select_src_candidate, get_end_of_func, get_loc_by_file_id
from normalizer.match_tool import ATTExParser, FactorList

from mapper.asmfile import AsmFileInfo, LocInfo, AsmInst
from collections import defaultdict


class JumpTable:
    def __init__(self, entries):
        self.entries = entries
        self.lengh = len(entries)
        self.base = 0

    def set_base(self, base):
        self.base = base

    def get_entries(self):
        pass

class CompData:
    def __init__(self, entries):
        self.entries = entries
        self.lengh = len(entries)
        self.base = 0

    def set_base(self, base):
        self.base = base

    def get_entries(self):
        pass

class FuncInst:
    def __init__(self, inst_list, func_info, asm_path):
        self.inst_list = inst_list
        self.name, self.addr, self.size = func_info
        self.asm_path = asm_path


def is_semantically_nop_str(inst_str):
    try:
        mnemonic = inst_str.split()[0]

        if mnemonic.startswith("nop"):
            return True
        if mnemonic[:3] == "lea" and mnemonic != 'leave':
            operand1 = inst_str.split(',')[0].split()[-1]
            operand2 = inst_str.split(',')[1].split()[-1]
            return operand1 == "(" + operand2 + ")"
        elif mnemonic[:3] == "mov" and not mnemonic.startswith("movs"):
            operand1 = inst_str.split(',')[0].split()[-1]
            operand2 = inst_str.split(',')[1].split()[-1]
            return operand1 == operand2
    except:
        assert False, 'unexpected instruction %s' % inst_str
    return False

def is_semantically_nop_token(inst_token):
    try:
        mnemonic = inst_token[0]

        if mnemonic.startswith("nop"):
            return True
        if mnemonic[:3] == "lea" and mnemonic != 'leave':
            if len(inst_token[1]) != 2:
                return False
            operand1 = inst_token[1][0]
            operand2 = inst_token[1][1]
            return operand1 == "(" + operand2 + ")"
        elif mnemonic[:3] == "mov" and not mnemonic.startswith("movs"):
            if len(inst_token[1]) != 2:
                return False
            operand1 = inst_token[1][0]
            operand2 = inst_token[1][1]
            return operand1 == operand2
    except:
        assert False, 'unexpected instruction %s' % str(inst_token)
    return False

def is_gcc_switch(opcode, operands, next_line):
    return opcode.startswith("jmp") and \
           operands[0][0] == "*" and \
           ".section" in next_line and \
           ".rodata" in next_line

def get_switch_entries(lines, sline):
    c = 0
    entries = []
    label_name = None
    for line in lines:
        c += 1
        if line.startswith(".L"):
            label_name = line.strip().split(":")[0]
            break
    sline += c - 1
    for line in lines[c:]:
        sline += 1
        if ".long" in line or ".quad" in line:
            if ".long" in line:
                esize = "long"
            else:
                esize = "quad"
            entries.append([line.split()[1], sline])
        else:
            break
    entries.append(esize)
    return label_name, entries

def src_get_insts(lines, base_idx):
    result = []
    jmptbl = {}
    c = -1
    is_rep = False
    labels = []
    label_name = []
    have_label = False

    for idx, line in enumerate(lines):
        if line.startswith(".L"):
            have_label = True
            label_name.append(line.split(":")[0])
        elif RE_INST.match(line):
            if have_label:
                #if not is_semantically_nop_str(line):
                labels.append((label_name, idx + base_idx))
                label_name = []
                have_label = False
                #else:
                #    print(line.strip(), file = sys.stderr)
            if is_rep:
                '''
                From:
                    rep(e)
                    stosb ...
                To:
                    rep(e) stosb ...
                '''
                is_rep = False
                inst_split = line.split("# ")[0].strip().split("\t")
                opcode += " " + inst_split[0]
                if len(inst_split) > 1:
                    operands = inst_split[1].split(", ")
                else:
                    operands = []
                result.append([opcode, operands, idx - 1 + base_idx])
                continue
            #if is_semantically_nop_str(line):
            #    continue
            if "cld; rep" in line:
                '''
                From:
                    cld; rep; movsb
                To:
                    cld
                    rep movsb
                '''
                result.append(["cld", [], idx + base_idx])
                result.append(["rep " + line.split("; ")[-1], [], idx + base_idx])
                continue

            inst_split = line.split("# ")[0].strip().split("\t")
            opcode = inst_split[0]
            if len(inst_split) > 1:
                operands = inst_split[1].split(", ")
            else:
                operands = []
                if opcode.startswith("rep;") or opcode.startswith("repe;"):
                    '''
                    rep;stosb\x20...
                    rep;movsb\x20...
                    '''
                    inst_split = opcode.split(" ", 1)
                    opcode = inst_split[0]
                    if len(inst_split) > 1:
                        operands = inst_split[1].split(", ")
                    else:
                        operands = []
                elif opcode.startswith("rep") and " " in opcode.strip():
                    operands = []
                elif opcode.startswith("rep"):
                    is_rep = True
                    continue
            if is_gcc_switch(opcode, operands, lines[idx+1]):
                lname, entries = get_switch_entries(lines[idx+2:], idx + 3 + base_idx)
                jmptbl[lname] = JumpTable(entries)
            result.append([opcode, operands, idx + base_idx])

    if len(label_name) != 0:
        labels.append((label_name, c + base_idx))

    return result, jmptbl, labels

def get_src_code(src_file, sline, eline):
    lines = src_file.split("\n")
    return src_get_insts(lines[sline:eline], sline)

def has_non_digits(s):
    digits = "0123456789+-"
    for c in s:
        if c not in digits:
            return True
    return False

def get_label_name(s):
    digits = "-0123456789"
    if len(s) == 0:
        return None
    elif s[0] in "*$":
        # e.g. *(%rsp)
        return get_label_name(s[1:])
    elif s[0] == "%":
        # e.g. %fs:40
        return None
    elif s[0] in digits:
        if has_non_digits(s):
            return s
        return None
    else:
        return s

def is_gotoff(s):
    if "@GOT" in s and not "@GOTPCREL" in s:
        return True
    else:
        return False

def get_label(s, v):
    if is_gotoff(s):
        return Label(s, LblTy.GOTOFF, v)
    else:
        return Label(s, LblTy.LABEL, v)

def get_label_value(s, v, infos, insn_addr):
    src_file, got, jmptbls, labels, hidden = infos
    if s == "_GLOBAL_OFFSET_TABLE_":
        value = got - insn_addr
    elif "@GOT" in s and not "@GOTPCREL" in s:
        s = s.split("@")[0]
        if s in jmptbls:
            if v != 0:
                value = got + v
                labels[s] = value
            else:
                value = labels[s]
        elif s in labels:
            value = labels[s]
        else:
            labels[s] = got + v
            value = got + v

        if s.startswith(".LJTI"):
            idx = src_file.find("\n" + s + ":")
            sline = len(src_file[:idx].splitlines()) + 1
            lines = src_file[idx + 1:].split("\n")
            _, jmptbls[s] = get_switch_entries(lines, sline)

    elif s.startswith(".L"):
        if s.startswith(".LJTI"):
            idx = src_file.find("\n" + s + ":")
            sline = len(src_file[:idx].splitlines()) + 1
            lines = src_file[idx + 1:].split("\n")
            _, jmptbls[s] = get_switch_entries(lines, sline)
        if s in jmptbls:
            if v != 0:
                value = v
                labels[s] = v
            else:
                value = labels[s]
        elif s in labels:
            value = labels[s]
        else:
            labels[s] = v
            value = v
    else:
        value = v
    return value, (src_file, got, jmptbls, labels, hidden)

def has_label(s):
    return s[0] not in '0123456789+-'

def get_const_term(tokens):
    expr = ''
    for token in tokens:
        if has_label(token):
            expr += '0'
        else:
            expr += token
    return eval(expr)

def is_operator(c):
    return c == '+' or c == '-'

def reduce_const_term(tokens):
    const = get_const_term(tokens)
    tokens_ = []
    i = 0
    while i < len(tokens):
        if has_label(tokens[i]):
            tokens_.append(tokens[i])
        i += 1
    return tokens_, const

def update_hidden_label_addr(label, value, infos, spath):
    s, g, j, l, hidden = infos
    if label in hidden:
        path, addrs = hidden[label][0]
        if path.split(":")[0] == spath:
            addrs.append(value)
            hidden[label][0] = [path, addrs]
    return (s, g, j, l, hidden)

def parse_expr(s, v, infos, insn_addr, spath):
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
            if c not in '()':
                token += c
    tokens.append(token)
    tokens, const = reduce_const_term(tokens)
    terms = []

    v -= const
    for token in tokens:
        if not is_operator(token):
            if infos:
                value, infos = get_label_value(token, v, infos, insn_addr)
                infos = update_hidden_label_addr(token, value, infos, spath)
            else:
                value = v
            lbl = get_label(token, value)
            terms.append(lbl)

    if const != 0:
        terms.append(const)

    return terms, infos


def parse_components(insn, src, infos, spath):
    digits = "-0123456789"
    insn_operands = insn.operands
    result = []

    if len(insn_operands) - len(src[1]) == 1:
        result.append(Component())
        insn_operands = insn_operands[1:]
    for idx, i in enumerate(insn_operands):
        if len(src[1]) == 0:
            # e.g. repne scasb (%rdi), %al
            #      ['repnz scasb', []]
            result.append(Component())
            continue
        else:
            s = src[1][idx]
        if i.type == X86_OP_REG:
            result.append(Component())
            continue
        elif i.type == X86_OP_IMM:
            is_pcrel = False
            if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                is_pcrel = True
            label_name = get_label_name(s)
            if label_name:
                value = i.imm
                terms, infos = parse_expr(label_name, value, infos, insn.address, spath)
                result.append(Component(terms, value, is_pcrel))
            else:
                result.append(Component())
                continue
        elif i.type == X86_OP_MEM:
            disp = s.split("(")[0]
            is_pcrel = False
            if len(disp) > 0:
                label_name = get_label_name(disp)
                if label_name:
                    if i.mem.base == X86_REG_RIP:
                        value = insn.address + insn.size + i.mem.disp
                        is_pcrel = True
                    else:
                        value = i.mem.disp
                    terms, infos = parse_expr(label_name, value, infos, insn.address, spath)
                    result.append(Component(terms, value, is_pcrel))
                else:
                    result.append(Component())
                    continue
            else:
                result.append(Component())
                continue
    return result, infos

def gen_prog(bin_path):
    elf = load_elf(bin_path)
    cs = get_disassembler(get_arch(elf))
    # Configurate Disassembler
    cs.detail = True
    cs.syntax = capstone.CS_OPT_SYNTAX_ATT
    prog = Program(elf, cs)
    return prog, elf, cs

def is_semantically_nop(inst):
    try:
        if inst.mnemonic.startswith("nop"):
            return True
        elif inst.mnemonic[:3] == "lea" and inst.mnemonic != 'leave':
            operands = inst.op_str.split(", ")
            return operands[0] == "(" + operands[1] + ")"
        elif inst.mnemonic[:3] == "mov":
            operands = inst.op_str.split(", ")
            return operands[0] == operands[1]
    except:
        assert False, 'unexpected instruction %s' % (inst)
    return False

def disasm(prog, cs, addr, length):
    offset = addr - prog.text_base
    insts = []
    for inst in prog.disasm_range(cs, addr, length):
        #if not is_semantically_nop(inst):
        insts.append(inst)
    return insts

def addressing_labels(_labels, src_code, insts):
    src_idx = 0
    code_idx = 0
    labels = {}
    for label, line in _labels:
        for code in src_code[src_idx:]:
            if is_semantically_nop(insts[code_idx]) and not is_semantically_nop_token(code):
                while is_semantically_nop(insts[code_idx]):
                    code_idx += 1
            if code[-1] == line:
                for lname in label:
                    labels[lname] = insts[code_idx].address
                src_idx += 1
                code_idx += 1
                break
            src_idx += 1
            code_idx += 1
    return labels

def get_instrs(prog, elf, src_code, bin_code, infos, spath, nop_insts):
    for i in range(len(bin_code)):
        inst = bin_code[i]
        addr = inst.address
        line = src_code[i][-1]
        components, infos = parse_components(inst, src_code[i], infos, spath)
        for c in components:
            lbls = c.get_labels()
            if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                c.Value += prog.get_got_addr(elf)
        prog.Instrs[addr] = Instr(addr, components, spath, line)
    for item in nop_insts:
        prog.Instrs[item.address] = Instr(item.address, [], spath, 0)
    return prog, infos

def get_entry_size(elf, ty):
    if ty == "long":
        esize = 4
    else:
        esize = 8
    return esize

def get_tables(prog, elf, infos, spath):
    _, _, tbl, labels, _ = infos
    for name in tbl:
        entries = []
        addr = labels[name]
        _entries = tbl[name]
        esize = get_entry_size(elf, _entries[-1])
        eaddr = addr
        for entry in _entries[:-1]:
            entry_expr, entry_line = entry
            terms, _ = parse_expr(entry_expr, 0, infos, 0, spath)
            component = Component(terms)
            data = Data(eaddr, component, spath, entry_line)
            #print(hex(eaddr))
            prog.Data[eaddr] = data
            eaddr += esize
        #prog.Tables[addr] = Table(name, addr, entries, esize)
    return prog

def get_reloc_bytesize(rinfo_type):
    if 'X86_64_' in rinfo_type and '32' not in rinfo_type:
        return 8
    else:
        return 4

def get_reloc_gotoff(rinfo_type):
    if 'GOTOFF' in rinfo_type:
        return True
    else:
        return False

def get_reloc(elf):
    relocs = {}

    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        if section.name.startswith(".rel") and \
           (("data" in section.name) or section.name.endswith(".dyn")):
            for relocation in section.iter_relocations():
                addr = relocation['r_offset']
                t = describe_reloc_type(relocation['r_info_type'], elf)
                sz = get_reloc_bytesize(t)
                is_got = get_reloc_gotoff(t)
                relocs[addr] = (sz, is_got)
    return relocs

def get_reloc_symbs(elf):
    names = {}
    dynsym = elf.get_section_by_name('.symtab')#('.dynsym')
    for symb in dynsym.iter_symbols():
        if symb['st_shndx'] != 'SHN_UNDEF':
            addr = symb['st_value']
            name = symb.name
            if addr != 0 and len(name) > 0:
                if name in names:
                    names[name].append(addr)
                else:
                    names[name] = [addr]
    return names

def get_composite_ms(path):
    visible_path = path + "/visible"
    hidden_path = path + "/hidden"

    visible_composites = {}
    hidden_composites = {}

    if os.path.exists(visible_path):
        for line in open(visible_path):
            line_s = line.strip().split()
            if line_s[1].endswith(":"):
                label = line_s[1][:-1]
                visible_composites[label] = []
            else:
                visible_composites[label].append((line_s[0], line_s[1:]))

    if os.path.exists(hidden_path):
        for line in open(hidden_path):
            line_s = line.strip().split()
            if line_s[1].endswith(":"):
                label = line_s[1][:-1]
                hidden_composites[label] = [(line_s[0], [])]
            else:
                # source path, expr, address
                hidden_composites[label].append((line_s[0], line_s[1:]))

    return visible_composites, hidden_composites

class NormalizeGT:
    def __init__(self, bin_path, asm_dir, work_dir='/data2/benchmark'):
        self.bin_path = bin_path
        self.asm_dir = asm_dir
        self.work_dir = work_dir

        self.collect_loc_candidates()
        with open(self.bin_path, 'rb') as f:
            elf = ELFFile(f)

            self.text = elf.get_section_by_name(".text")
            self.text_base = self.text.header["sh_addr"]

            if "x64" in self.bin_path.split('/'):
                self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

            self.cs.detail = True
            self.cs.syntax = capstone.CS_OPT_SYNTAX_ATT
            disassembly = self.cs.disasm(self.text.data(), self.text_base)

            self.instructions = {}  # address : instruction
            for instruction in disassembly:
                self.instructions[instruction.address] = instruction

            self.instruction_addrs = list(self.instructions.keys())
            self.instruction_addrs.sort()

        self.elf = load_elf(bin_path)
        self.prog = Program(self.elf, self.cs)

        self.got_addr = self.elf.get_section_by_name('.got.plt')['sh_addr']
        self.relocs = get_reloc(self.elf)
        self.symbs = get_reloc_symbs(self.elf)

        #self.visible, self.hidden = get_composite_ms(self.composite_dir)

        print('match_src_to_bin')
        self.match_src_to_bin()
        #print('map_func')
        #self.addressed_asms, self.addressed_data = self.map_func()




    def map_func(self):
        addressed_asms = {}
        addressed_data = {}

        #src_files = {}
        tables = []

        for _, func in self.bin2src_dict.items():

            #spath, sline, eline = loc
            #faddr = int(func.addr)
            insts = disasm(self.prog, self.cs, func.addr, func.size)
            '''
            spath_full = os.path.join(self.work_dir, spath[1:])
            if spath not in src_files:
                src_files[spath] = open(spath_full, errors='ignore').read()

            src_file = src_files[spath]

            src_code, tbl, _labels = get_src_code(src_file, sline, eline)
            labels = addressing_labels(_labels, src_code, insts)

            for label, _ in _labels:
                for lname in label:
                    if lname not in labels:
                        # This only happens in '-os' optimization
                        # except .Lfunc_end*
                        labels[lname] = faddr + func.size
            '''
            insts, asm_code, nop_insts = self.separate_nop(insts, func.inst_list)

            if len(insts) != len(asm_code):
                print(len(insts), len(asm_code))
                import pdb
                pdb.set_trace()
                #print('\n'.join([self.bin_path, func.name, os.path.join(self.work_dir, spath), str(sline)]), '\n')
                raise

            #infos = (src_file, self.got_addr, tbl, labels, self.hidden)
            #spath_full = os.path.join(self.work_dir, spath)
            for idx in range(len(insts)):
                inst = insts[idx]
                addr = inst.address
                asm = asm_code[idx]
                #no = _code.idx
                #tokens = src_code[idx][:-1]

                components = self.parse_components(inst, asm, func)

                for c in components:
                    lbls = c.get_labels()
                    if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                        c.Value += self.got_address

                addressed_asms[addr] = Instr(addr, components, func.asm_path, asm.idx)

                #addressed_asms.append((addr, tokens, spath, no))

        #for fd in src_files:
        #    fd.close()

        return addressed_asms, addressed_data

    def separate_nop(self, insts, asm_list):
        new_insts = []
        new_asm_code = []

        nop_insts = []
        for inst in insts:
            if not self.is_semantically_nop(inst):
                new_insts.append(inst)
            else:
                nop_insts.append(inst)
        for asm in asm_list:
            if not self.is_semantically_nop(asm):
                new_asm_code.append(asm)

        return new_insts, new_asm_code, nop_insts

    def is_semantically_nop(self, inst):
        if isinstance(inst, capstone.CsInsn):
            mnemonic = inst.mnemonic
            operand_list = inst.op_str.split(', ')
        elif isinstance(inst, AsmInst):
            mnemonic = inst.opcode
            operand_list = inst.operands

        try:
            if mnemonic.startswith("nop"):
                return True
            if mnemonic[:3] == "lea" and mnemonic != 'leave':
                return operand_list[0] == "(" + operand_list[1] + ")"
            elif mnemonic[:3] == "mov" and not mnemonic.startswith("movs"):
                return operand_list[0] == operand_list[1]
        except:
            assert False, 'unexpected instruction %s' % ' '.join(operand_list)
        return False


    def parse_components(self, insn, asm_info, func_info, asm_file):
        operands = insn.operands
        components = []

        parser = ATTExParser()

        asm_operands = asm_info.operands

        label_dict = dict()
        for idx, operand in enumerate(operands):

            if len(asm_operands) <= idx:
                # sarl $1, %eax     vs. salr %eax
                # salw $1, -6(%rbp) vs. salw -6(%rbp)
                # shrq $1, %rax     vs. shrq %rax
                # shll $1, -0x3b4(%rbp) vs sall -948(%rbp)
                # shrl $1, -0x3b0(%rbp) vs shrl -944(%rbp)
                # shrw $1, -0x106(%rbp) vs shrw -262(%rbp)
                # sarq $1, %rdx     vs  sarq %rdx
                # sarl $1, %eax     vs  sarl %eax
                # shrw $1, -0x106(%rbp) vs. shrw -262(%rbp)
                # shrb $1, %al          vs. shrb %al
                # repne scasb (%rdi), %al vs. repnz scasb
                # rep movsq (%rsi), (%rdi) vs. rep movsq
                if asm_info.opcode in ['salq', 'salw', 'shrq', 'sarq', 'shll', 'sall', 'shrw', 'shrl', 'sarl', 'shrb']:
                    pass
                elif asm_info.opcode in ['repnz scasb', 'rep stosq', 'rep movsq']:
                    pass
                else:
                    print(insn)
                    print('%s %s'%(asm_info.opcode, ' '.join(asm_info.operands)))
                break

            op_str = asm_operands[idx]
            if operand.type == X86_OP_REG:
                components.append(Component())
                continue
            elif operand.type == X86_OP_IMM:
                is_pcrel = False
                value = operand.imm
                if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                    is_pcrel = True

                '''
                label_name = get_label_name(op_str)
                if label_name:
                    terms, infos = parse_expr(label_name, value, infos, insn.address, spath)
                    components.append(Component(terms, value, is_pcrel))
                else:
                    components.append(Component())
                '''
            elif operand.type == X86_OP_MEM:
                is_pcrel = False
                value = operand.mem.disp
                if operand.mem.base == X86_REG_RIP:
                    is_pcrel = True

                '''
                disp = s.split("(")[0]
                is_pcrel = False
                if len(disp) > 0:
                    label_name = get_label_name(disp)
                    if label_name:
                        if i.mem.base == X86_REG_RIP:
                            value = insn.address + insn.size + i.mem.disp
                            is_pcrel = True
                        else:
                            value = i.mem.disp
                        terms, infos = parse_expr(label_name, value, infos, insn.address, spath)
                        components.append(Component(terms, value, is_pcrel))
                    else:
                        components.append(Component())
                        continue
                else:
                    components.append(Component())
                    continue
                '''
            else:
                continue

            if is_pcrel:
                value += insn.address + insn.size
            elif '@GOTOFF' in op_str:
                value += self.got_addr

            if op_str == "_GLOBAL_OFFSET_TABLE_":
                gotoff = self.got_addr - insn.address
            else:
                gotoff = 0

            factors = FactorList(parser.parse(op_str), value, label_dict, gotoff)

            if factors.has_label():
                components.append(Component(factors.get_terms(), value, is_pcrel, factors.get_str()))
            else:
                components.append(Component())

            if factors.has_label():
                self.update_labels(func_info, factors, asm_file)

        return components


    def update_table(self, addr, comp_data, asm_path):
        parser = ATTExParser()
        for line, idx in comp_data.members:
            directive = line.split()[0]
            if directive in ['.long']:
                sz = 4
            elif directive in ['.quad']:
                sz = 1
            else:
                assert False, 'Unsupported jump table entries'

            [label1, label2] = line.split()[1].split('-')
            assert label2 == comp_data.label
            op_str = '%s-%d'%(label1, comp_data.addr)

            value = get_int(self.elf, addr, sz)

            factors = FactorList(parser.parse(op_str), value)

            #import pdb
            #pdb.set_trace()

            component = Component(factors.get_terms(mask=True), value,  False, self.got_addr)
            self.prog.Data[addr] = Data(addr, component, asm_path, idx+1)
            #print('jmp table: %s - %s'%(hex(factors.get_terms(mask=True)[0].get_value()), hex(comp_data.addr)))

            addr += sz


    def update_data(self, addr, comp_data, asm_path):
        parser = ATTExParser()
        for line, idx in comp_data.members:
            directive = line.split()[0]
            if directive in ['.long']:
                sz = 4
            elif directive in ['.quad']:
                sz = 8
            elif directive in ['.word']:
                sz = 2
            elif directive in ['.byte']:
                sz = 1
            elif directive in ['.zero']:
                sz = int(line.split()[1])
            else:
                print(line)
                assert False, "unknown data type"

            op_str = ' '.join(line.split()[1:])
            if sz in [4,8] and re.search('.[+|-]', op_str):
                value = get_int(self.elf, addr, sz)
                factors = FactorList(parser.parse(op_str), value)

                if '@GOTOFF' in line:
                    value += self.got_addr

                component = Component(factors.get_terms(), value,  False, self.got_addr)
                self.prog.Data[addr] = Data(addr, component, asm_path, idx+1)

            addr += sz



    def update_labels(self, func_info, factors, asm_file): #label_dict, jmptbls, factors):
        target_addr = factors.value - factors.num
        for label in factors.labels:
            if label == '_GLOBAL_OFFSET_TABLE_':
                continue

            if '@GOT' in label and '@GOTPCREL' not in label:
                label = label.split('@')[0]

            if label in asm_file.composite_data and not asm_file.composite_data[label].addr:
                asm_file.composite_data[label].set_addr(target_addr)
            if label in asm_file.jmp_dict:
                asm_file.jmp_dict[label].set_addr(target_addr)
                #import pdb
                #pdb.set_trace()
                #self.update_data(target_addr, asm_file.composite_data[label], asm_file.file_path)
                #self.jmp_table_dict[func_info.asm_path][label].set_addr(value)
                #self.prog.Data[addr] = Data(value, component, asm_file.file_path, line)
            '''
            if label not in label_dict:
                label_dict[label] = value

                if label in jmptbls:
                    jmptbls[label].base = value

                if label in self.hidden:
                    pass
            '''
    '''
                components, infos = parse_components(inst, src_code[i], infos, spath)
                for c in components:
                    lbls = c.get_labels()
                    if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                        c.Value += prog.get_got_addr(elf)
                prog.Instrs[addr] = Instr(addr, components, spath, line)
            for item in nop_insts:
                prog.Instrs[item.address] = Instr(item.address, [], spath, 0)
    '''

    '''

            self.prog = get_tables(self.prog, self.elf, infos, spath_full)

    #def get_instrs(prog, elf, src_code, bin_code, infos, spath, nop_insts):
        for i in range(len(bin_code)):
            inst = bin_code[i]
            addr = inst.address
            line = src_code[i][-1]
            components, infos = parse_components(inst, src_code[i], infos, spath)
            for c in components:
                lbls = c.get_labels()
                if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                    c.Value += prog.get_got_addr(elf)
            prog.Instrs[addr] = Instr(addr, components, spath, line)
        for item in nop_insts:
            prog.Instrs[item.address] = Instr(item.address, [], spath, 0)
        return prog, infos
    #def get_tables(prog, elf, infos, spath):
        _, _, tbl, labels, _ = infos
        for name in tbl:
            entries = []
            addr = labels[name]
            _entries = tbl[name]
            esize = get_entry_size(elf, _entries[-1])
            eaddr = addr
            for entry in _entries[:-1]:
                entry_expr, entry_line = entry
                terms, _ = parse_expr(entry_expr, 0, infos, 0, spath)
                component = Component(terms)
                data = Data(eaddr, component, spath, entry_line)
                #print(hex(eaddr))
                prog.Data[eaddr] = data
                eaddr += esize
            #prog.Tables[addr] = Table(name, addr, entries, esize)
        return prog

    '''


    ##############

    def get_objdump(self):
        temp_file = self.bin_path.replace('/','_')
        os.system("objdump -t -f %s | grep \"F .text\" | sort > /tmp/xx%s" % (self.bin_path, temp_file))

        funcs = []
        for line in open("/tmp/xx" + temp_file):
            l = line.split()
            fname = l[-1]
            faddress = int(l[0], 16)
            fsize = int(l[4], 16)

            try:
                #if len(loc_candidates) and fsize > 0:
                if self.has_func_assem_file(fname) and fsize > 0:
                    funcs.append([fname, faddress, fsize])
            except:
                pass
        return funcs


    def update_instr(self, func_info):

        fname, faddress, fsize = func_info

        f_offset = faddress - self.text_base
        f_end_offset = f_offset + fsize
        dump = self.cs.disasm(self.text.data()[f_offset:f_end_offset], faddress)
        for inst in dump:
            if inst.address in self.instructions:
                break
            self.instructions[inst.address] = inst
            self.instruction_addrs.append(inst.address)
        instruction_addrs.sort()


    def match_src_to_bin(self):

        self.bin2src_dict = {}
        self.composite_data = dict()
        self.jmp_table_dict = dict()

        debug_loc_paths = {}
        src_files = {}

        #result = {}
        dwarf_loc = get_dwarf_loc(self.bin_path)

        funcs = self.get_objdump()   # [funcname, address, size] list
        for func_info in funcs:
            fname, faddress, fsize = func_info

            if '__x86.get_pc_thunk' in fname:
                continue

            #src_files = self.get_src_files(src_files, loc_candidates)
            #debug_loc_paths = get_loc_by_file_id(src_files, debug_loc_paths, loc_candidates)

            '''
            Handle weird padding bytes
            '''
            if faddress not in self.instructions:
                self.update_instr(func_info) #faddress, fsize)

            func_code = self.get_func_code(faddress, fsize)

            asm_file, addressed_asm_list = self.find_match_func(func_code, func_info)

            #asm_inst_list = [line for line in asm_file.func_dict[fname] if isinstance(line, AsmInst)]
            #addressed_asm_list = self.assem_addr_map(func_code, asm_inst_list)

            self.bin2src_dict[faddress] = FuncInst(addressed_asm_list, func_info, asm_file.file_path)
            for addr, capstone_insn, asm in addressed_asm_list:

                components = self.parse_components(capstone_insn, asm, self.bin2src_dict[faddress], asm_file)

                for com in components:
                    lbls = com.get_labels()
                    if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                        com.Value += self.got_address

                self.prog.Instrs[addr] = Instr(addr, components, asm_file.file_path, asm.idx+1)

            '''
            if asm_file.file_path not in self.composite_data:
                self.composite_data[asm_file.file_path] = asm_file.composite_data
                self.jmp_table_dict[asm_file.file_path] = asm_file.jmp_dict
            '''



        text_end = self.text.data_size + self.text_base
        prev_end = self.text_base
        unknown_region = set()
        for faddress in sorted(self.bin2src_dict.keys()):
            unknown_region.update(range(prev_end, faddress))
            prev_end = faddress + self.bin2src_dict[faddress].addr
        unknown_region.update(range(prev_end, text_end))
        self.prog.unknown_region = unknown_region



    def is_semantically_same(self, insn, asm):

        if insn.mnemonic[:-1] == asm.opcode:
            return True
        if insn.mnemonic == asm.opcode[:-1]:
            return True
        if insn.mnemonic.startswith('rep') and asm.opcode.startswith('rep'):
            if insn.mnemonic.split()[1] == asm.opcode.split()[1]:
                return True
        if insn.group(capstone.CS_GRP_JUMP):
            jumps = [
                ["jo"],
                ["jno"],
                ["js"],
                ["jns"],
                ["je", "jz"],
                ["jne", "jnz"],
                ["jb", "jna", "jc"],
                ["jnb", "jae", "jnc"],
                ["jbe", "jna"],
                ["ja", "jnb"],
                ["jl", "jng"],
                ["jge", "jnl"],
                ["jle", "jng"],
                ["jg", "jnl"],
                ["jp", "jpe"],
                ["jnp", "jpo"],
                ["jcx", "jec"]
            ]
            for jump in jumps:
                if insn.mnemonic in jump and asm.opcode in jump:
                    return True
        else:
            opcodes = [
                ['sall', 'shll'],
                ['shlq', 'salq'],
                ["shl", "sal"],
                ['leaq', 'movq'],
                ['setae', 'setnb'],
                ['cmovael', 'cmovnb'],
                ['shlw', 'salw'],
                #["ret", "rep"], # retq == rep retn
            ]
            for opcode in opcodes:
                if insn.mnemonic in opcode and asm.opcode in opcode:
                    return True

            if insn.mnemonic in ['addq'] and asm.opcode in ['subq']:
                if asm.operands[0].startswith('$-'):
                    return True

            capstone_bugs = [
                ['movd', 'movq'],
                ['cmovaeq', 'cmovnb'],
            ]
            for opcode in capstone_bugs:
                if insn.mnemonic in opcode and asm.opcode in opcode:
                    return True

        return False



    def assem_addr_map(self, func_code, asm_list, candidate_len):

        addressed_asm_list = []
        idx = 0
        for bin_asm in func_code:
            asm = asm_list[idx]

            if asm.opcode == bin_asm.mnemonic:
                addressed_asm_list.append((bin_asm.address, bin_asm, asm))
            elif self.is_semantically_same(bin_asm, asm):
                addressed_asm_list.append((bin_asm.address, bin_asm, asm))
            elif self.is_semantically_nop(bin_asm):
                if self.is_semantically_nop(asm):
                    addressed_asm_list.append((bin_asm.address, bin_asm, asm))
                else:
                    addressed_asm_list.append((bin_asm.address, bin_asm, ''))
                    continue
            else:
                if candidate_len > 1:
                    return []
                print(bin_asm)
                print('%s %s'%(asm.opcode, ' '.join(asm.operands)))
                import pdb
                pdb.set_trace()
                addressed_asm_list.append((bin_asm.address, bin_asm, asm))
                #return []
                #assert False, 'Unexpacted instruction sequence'
            idx += 1

        if idx < len(asm_list):
            #assert False, 'Unexpacted instruction sequence'
            return []

        return addressed_asm_list

    def find_match_func(self, func_code, func_info):

        fname, faddress, fsize = func_info
        if not self.has_func_assem_file(fname):
            return None

        #if len(self.func_dict[fname]) == 1:
        #    return self.func_dict[fname][0]

        '''
        #Debug
        if len(locs) == 1:
            return locs
        '''
        #import pdb
        #pdb.set_trace()
        ret = []
        candidate_list = self.get_assem_file(fname)
        candidate_len = len(candidate_list)
        for asm_file in candidate_list:

            asm_inst_list = [line for line in asm_file.func_dict[fname] if isinstance(line, AsmInst)]

            addressed_asm_list = self.assem_addr_map(func_code, asm_inst_list, candidate_len)

            if not addressed_asm_list:
                continue
            ret.append((asm_file, addressed_asm_list))


        if not ret:
            import pdb
            pdb.set_trace()
            assert False, 'No matched assembly code'
        if len(ret) == 1:
            return ret[0]

        import pdb
        pdb.set_trace()





        matched_locs = []
        mov_lea = ["mov", "lea"]
        for loc in locs:
            line = int(loc[1].split("@")[1])
            lines = src_files[loc[0]].split("\n")[line-1:]
            src_insts = src_get_insts(lines, len(func_code))
            src_insts_len = len(src_insts)
            match_cnt = 0
            bin_nop_cnt = 0
            src_nop_cnt = 0
            for idx, inst in enumerate(func_code):
                if src_insts_len - src_nop_cnt <= idx - bin_nop_cnt:
                    break
                src_idx = idx - bin_nop_cnt + src_nop_cnt
                src_op = src_insts[src_idx].split()[0][:3].lower()
                bin_op = inst.mnemonic.lower()[:3]
                #DEBUG
                #print(inst.mnemonic, inst.op_str, '\t', src_insts[src_idx])
                if is_semantically_nop(inst):
                    # compile might emit nop code
                    if is_semantically_nop_str(src_insts[src_idx]):
                        src_nop_cnt += 1
                    bin_nop_cnt += 1
                    continue
                while True:
                    if src_op == "nop":
                        src_nop_cnt += 1
                        src_idx = idx - bin_nop_cnt + src_nop_cnt
                        if src_idx >= len(src_insts):
                            # bin_op != "nop"
                            # src_op == "nop"
                            # So next loc will be processed
                            break
                        src_op = src_insts[src_idx].split()[0][:3].lower()
                    else:
                        break
                if bin_op != src_op:
                    if is_semantically_same(src_op, bin_op):
                        match_cnt += 1
                    elif src_op[0] == "j" and bin_op[0] == "j" and is_same_jump(src_op, bin_op):
                        match_cnt += 1
                    else:
                        #print(hex(inst.address), inst.mnemonic, [inst.op_str], src_insts[src_idx])
                        break
                else:
                    match_cnt += 1
            #DEBUG
            #print(match_cnt, len(func_code), bin_nop_cnt)
            #print(func_code[-1].mnemonic, func_code[-1].op_str)
            if match_cnt == len(func_code) - bin_nop_cnt:
                matched_locs.append(loc)
        if len(matched_locs) == 0:
            print("No candidate. Impossible", file=sys.stderr)
            print(binpath, hex(faddress), fname, loc_candidates, file=sys.stderr)
            return None


        if len(asm_file_list) == 1:
            return asm_file_list[0]

        asm_inst_list = [line for line in asm_file_list[0].func_dict[fname] if isinstance(line, AsmInst)]
        import pdb
        pdb.set_trace()

        candidate = select_src_candidate(dwarf_loc, faddress, src_files, res, debug_loc_paths)
        if not candidate:
            res = [res[0]]
        else:
            res = [candidate]






    def get_func_code(self, address, size):
        try:
            result = []
            idx = self.instruction_addrs.index(address)
            curr = address
            while True:
                if curr >= address + size:
                    break
                inst = self.instructions[curr]
                result.append(inst)
                curr += inst.size
            return result
        except:
            print("Disassembly failed. Impossible")
            exit()



    def get_src_files(self, src_files, loc_candidates):
        for loc_path, _ in loc_candidates:
            if loc_path not in src_files.keys():
                loc_path_full = os.path.join(self.work_dir, loc_path[1:])
                f = open(loc_path_full, errors='ignore')
                src_files[loc_path] = f.read()
        return src_files


    def get_src_paths(self):
        srcs = []
        for i in range(20):
            t = "*/" * i
            srcs += glob.glob(self.asm_dir + t + "*.s")
        return srcs

    def has_func_assem_file(self, func_name):
        return func_name in self._func_map

    def get_assem_file(self, func_name):
        ret = []
        for asm_path in self._func_map[func_name]:
            ret.append(self.asm_file_dict[asm_path])
        return ret



    def collect_loc_candidates(self):

        srcs = self.get_src_paths()
        #result = {}

        self._func_map = defaultdict(list)
        self.asm_file_dict = dict()

        for src in srcs:
            asm_file = AsmFileInfo(src)
            asm_file.scan()
            self.asm_file_dict[src] = asm_file
            for func_name in asm_file.func_dict.keys():
                self._func_map[func_name].append(src)

            '''
            cnt = 0
            for line in open(src, errors='ignore'):
                cnt += 1
                line = str(line)
                if RE_FUNC.match(line):
                    path = src[len(self.work_dir):]

                    #if 'spec_cpu2006' in self.asm_dir:
                    #    bin_name = os.path.basename(self.bin_path)
                    #    if '/asm/%s/'%(self.bin_name) not in path:
                    #        continue

                    #print(path)
                    fname = line.split(":")[0]
                    if fname not in result.keys():
                        result[fname] = []
                    result[fname].append([path, "line@%d" % cnt])
            '''
        #return result



    def normalize_inst(self):
        '''
        src_files = {}
        tables = []

        for faddress, (fname, fsize, loc) in self.bin2src_dict.items():

            #fname, fsize, loc = match_info[faddress]
            spath, sline, eline = loc
            faddr = int(faddress)
            insts = disasm(self.prog, self.cs, faddr, fsize)
            if spath not in src_files:
                spath_full = os.path.join(self.work_dir, spath[1:])
                f = open(spath_full, errors='ignore').read()
                src_files[spath] = f

            src_file = src_files[spath]

            src_code, tbl, _labels = get_src_code(src_file, sline, eline)
            labels = addressing_labels(_labels, src_code, insts)

            for label, _ in _labels:
                for lname in label:
                    if lname not in labels:
                        # This only happens in '-os' optimization
                        # except .Lfunc_end*
                        labels[lname] = faddr + fsize

            insts, src_code, nop_insts = separate_nop(insts, src_code)

            if len(insts) != len(src_code):
                print(len(insts), len(src_code))
                print('\n'.join([self.bin_path, fname, os.path.join(self.work_dir, spath), str(sline)]), '\n')
                raise

            infos = (src_file, self.got_addr, tbl, labels, self.hidden)
            spath_full = os.path.join(self.work_dir, spath)

            self.prog, infos = get_instrs(self.prog, self.elf, src_code, insts, infos, spath_full, nop_insts)
            self.prog = get_tables(self.prog, self.elf, infos, spath_full)

        '''

        for faddress, func_info in self.bin2src_dict.items():
            import pdb
            pdb.set_trace()
            for addr, inst in func_info.inst_list:
                #prog.Instrs[addr] = Instr(addr,  , func_info.asm_path, inst.idx+1)
                pass
        #prog.Instrs[addr] = Instr(addr, components, spath, line)

        text_end = self.text.data_size + self.text_base
        prev_end = self.text_base
        unknown_region = set()
        for faddress in sorted(self.bin2src_dict.keys()):
            unknown_region.update(range(prev_end, faddress))
            prev_end = faddress + self.bin2src_dict[faddress].addr
        unknown_region.update(range(prev_end, text_end))
        self.prog.unknown_region = unknown_region

    def normalize_data(self):
        '''
        def get_composite_datas(exprs, addr):
            for spath, expr in exprs:
                ty = expr[0]
                if ty == ".long":
                    sz = 4
                elif ty == ".quad":
                    sz = 8
                elif ty == ".zero":
                    sz = int(expr[1])
                else:   # .byte
                    sz = 1

                if "+" not in expr[1]:
                    addr += sz
                else:
                    value = get_int(elf, addr, sz)
                    terms, _ = parse_expr(expr[1], value, None, None, None)
                    component = Component(terms, value)
                    path = spath.split(":")[0]
                    line = int(spath.split(":")[1])
                    self.prog.Data[addr] = Data(addr, component, path, line)

        import pdb
        pdb.set_trace()
        for label in self.visible:
            if label not in self.symbs:
                continue
            for base in self.symbs[label]:
                get_composite_datas(self.visible[label], base)

        for label in self.hidden:
            for base in self.hidden[label][0][1]:
                get_composite_datas(self.hidden[label][1:], base)
        '''

        visited_label = []
        for asm_path, asm_file in self.asm_file_dict.items():
            for label, comp_data in asm_file.composite_data.items():
                if comp_data.addr:
                    self.update_data(comp_data.addr, comp_data, asm_path)
                    visited_label.append(label)

        for asm_path, asm_file in self.asm_file_dict.items():
            for label, comp_data in asm_file.composite_data.items():
                if not comp_data.addr:
                    if label in self.symbs and len(self.symbs[label]) == 1 and label not in visited_label:
                        self.update_data(self.symbs[label][0], comp_data, asm_path)
                        visited_label.append(label)
                    else:
                        print('unknown comp data %s:%s'%(asm_path, label))



        comp_set = set(self.prog.Data.keys())
        reloc_set = set(self.relocs)

        #import pdb
        #pdb.set_trace()
        if comp_set - reloc_set:
            import pdb
            pdb.set_trace()
            print(comp_set - reloc_set)

        for asm_path, asm_file in self.asm_file_dict.items():
            for label, comp_data in asm_file.jmp_dict.items():
                if comp_data.addr:
                    self.update_table(comp_data.addr, comp_data, asm_path)
                    visited_label.append(label)



        for addr in self.relocs:
            if addr in self.prog.Data:
                # composite ms || already processed
                continue
            sz, is_got = self.relocs[addr]
            value = get_int(self.elf, addr, sz)
            if is_got:
                value += self.got_addr
                lbl = get_label("Label_blah@GOTOFF", value)
            else:
                lbl = get_label("Label_blah", value)
            component = Component([lbl], value)
            # If we already have addr, it means it should be a jump table
            if addr not in self.prog.Data:
                self.prog.Data[addr] = Data(addr, component, '', 0)




def print_instrs(prog):
    for key in prog.Instrs:
        print(hex(key), end='\t')
        inst = prog.Instrs[key]
        for component in inst.Components:
            sys.stdout.write("[ ")
            for term in component.Terms:
                if isinstance(term, Label):
                    print("(%s : %x), " % (term.get_type(), term.get_value()), end='')
                else:
                    print("(int : %x), " % (term))
            sys.stdout.write(" ], ")
            prog.Instrs[key].Components
        print("")


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_gt')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('asm_dir', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    gt = NormalizeGT(args.bin_path, args.asm_dir)
    #gt.normalize_inst()
    gt.normalize_data()

    with open(args.save_file, 'wb') as f:
        pickle.dump(gt.prog, f)

