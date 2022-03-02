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
from mapper.match_src_to_bin import get_dwarf_loc, find_match_func, select_src_candidate, get_end_of_func, get_loc_by_file_id

def is_semantically_nop_str(inst_str):
    try:
        new_inst_str = inst_str.split('#')[0]
        mnemonic = new_inst_str.split()[0]

        if mnemonic.startswith("nop"):
            return True
        if mnemonic[:3] == "lea" and mnemonic != 'leave':
            operand1 = new_inst_str.split(',')[0].split()[-1]
            operand2 = new_inst_str.split(',')[1].split()[-1]
            return operand1 == "(" + operand2 + ")"
        elif mnemonic[:3] == "mov" and not mnemonic.startswith("movs"):
            operand1 = new_inst_str.split(',')[0].split()[-1]
            operand2 = new_inst_str.split(',')[1].split()[-1]
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

def src_get_insts(lines, sline):
    result = []
    jmptbl = {}
    c = -1
    is_rep = False
    labels = []
    label_name = []
    have_label = False

    for line in lines:
        c += 1
        if line.startswith(".L"):
            have_label = True
            label_name.append(line.split(":")[0])
        elif RE_INST.match(line):
            if have_label:
                #if not is_semantically_nop_str(line):
                labels.append((label_name, c + sline))
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
                result.append([opcode, operands, c - 1 + sline])
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
                result.append(["cld", [], c + sline])
                result.append(["rep " + line.split("; ")[-1], [], c + sline])
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
            if is_gcc_switch(opcode, operands, lines[c+1]):
                lname, entries = get_switch_entries(lines[c+2:], c + 3 + sline)
                jmptbl[lname] = entries
            result.append([opcode, operands, c + sline])

    if len(label_name) != 0:
        labels.append((label_name, c + sline))

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

def separate_nop(insts, src_code):
    new_insts = []
    new_src_code = []

    nop_insts = []
    for inst in insts:
        if not is_semantically_nop(inst):
            new_insts.append(inst)
        else:
            nop_insts.append(inst)
    for code in src_code:
        if not is_semantically_nop_token(code):
            new_src_code.append(code)

    return new_insts, new_src_code, nop_insts

class NormalizeGT:
    def __init__(self, bin_path, asm_dir, composite_dir, work_dir='/data2/benchmark'):
        self.bin_path = bin_path
        self.asm_dir = asm_dir
        self.composite_dir = composite_dir
        self.work_dir = work_dir

        self.func_dict = self.collect_loc_candidates()
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

        self.bin2src_dict, self.unknown_funcs = self.match_src_to_bin()

        self.elf = load_elf(bin_path)
        self.prog = Program(self.elf, self.cs)

        self.got_addr = self.elf.get_section_by_name('.got.plt')['sh_addr']
        self.relocs = get_reloc(self.elf)
        self.symbs = get_reloc_symbs(self.elf)

        self.visible, self.hidden = get_composite_ms(self.composite_dir)

    def get_objdump(self):
        temp_file = self.bin_path.replace('/','_')
        os.system("objdump -t -f %s | grep \"F .text\" | sort > /tmp/xx%s" % (self.bin_path, temp_file))

        funcs = []
        unknown_funcs = dict()
        for line in open("/tmp/xx" + temp_file):
            l = line.split()
            fname = l[-1]
            faddress = int(l[0], 16)
            fsize = int(l[4], 16)

            try:
                loc_candidates = self.func_dict[fname]
                if len(loc_candidates) and fsize > 0:
                    funcs.append([fname, faddress, fsize, loc_candidates])
            except:
                unknown_funcs[faddress] = [fname, faddress, fsize]
        return funcs, unknown_funcs


    def update_instr(self, faddress, fsize):
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

        debug_loc_paths = {}
        src_files = {}

        result = {}
        dwarf_loc = get_dwarf_loc(self.bin_path)

        funcs, unknown_funcs = self.get_objdump()   # [funcname, address, size] list
        for func in funcs:
            fname, faddress, fsize, loc_candidates = func
            src_files = self.get_src_files(src_files, loc_candidates)
            debug_loc_paths = get_loc_by_file_id(src_files, debug_loc_paths, loc_candidates)

            '''
            Handle weird padding bytes
            '''
            if faddress not in self.instructions:
                self.update_instr(faddress, fsize)

            func_code = self.get_func_code(faddress, fsize)
            res = find_match_func(src_files, loc_candidates, func_code)

            if not res:
                #HSKIM: intrinsic functions might not have debug info
                if '__x86.get_pc_thunk' in fname:
                    continue

                print("No candidate. Impossible", file=sys.stderr)
                print(binpath, hex(faddress), fname, loc_candidates, file=sys.stderr)
                break
            else:
                if len(res) > 1:
                    candidate = select_src_candidate(dwarf_loc, faddress, src_files, res, debug_loc_paths)
                    if not candidate:
                        res = [res[0]]
                    else:
                        res = [candidate]
                res = get_end_of_func(src_files, res)
                result[faddress] = [fname, fsize] + res

        return result, unknown_funcs

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

    def collect_loc_candidates(self):

        srcs = self.get_src_paths()
        result = {}

        for src in srcs:
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

        return result



    def normalize_inst(self):
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
            self.prog.unknown_funcs = self.unknown_funcs


    def normalize_data(self):
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

        for label in self.visible:
            if label not in self.symbs:
                continue
            for base in self.symbs[label]:
                get_composite_datas(self.visible[label], base)

        for label in self.hidden:
            for base in self.hidden[label][0][1]:
                get_composite_datas(self.hidden[label][1:], base)

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
    parser.add_argument('composite_dir', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    gt = NormalizeGT(args.bin_path, args.asm_dir, args.composite_dir)
    gt.normalize_inst()
    gt.normalize_data()

    with open(args.save_file, 'wb') as f:
        pickle.dump(gt.prog, f)

