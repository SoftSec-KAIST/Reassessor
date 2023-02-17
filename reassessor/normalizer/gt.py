import re
import struct
import capstone
import sys
import os
import pickle
import glob, json
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.relocation import RelocationSection
from collections import defaultdict

from reassessor.lib.types import Program, InstType, LblTy, Label
from reassessor.lib.parser import CompGen
from reassessor.lib.asmfile import AsmFileInfo, LocInfo, AsmInst

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
        self.jmp_table_list = []

    def register_jmp_table(self, inst_addr, label, tbl_addr, tbl_size):
        self.jmp_table_list.append({'inst_addr':inst_addr, 'label':label, 'addr':tbl_addr, 'size':tbl_size})

def get_dwarf_loc(filename):
    dwarf_loc_map = {}

    def process_file(filename):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)

            if not elffile.has_dwarf_info():
                print('  file has no DWARF info')
                return

            dwarfinfo = elffile.get_dwarf_info()
            for CU in dwarfinfo.iter_CUs():
                line_program = dwarfinfo.line_program_for_CU(CU)
                if line_program is None:
                    continue
                line_entry_mapping(line_program)

    def line_entry_mapping(line_program):
        lp_entries = line_program.get_entries()
        for lpe in lp_entries:
            if not lpe.state or lpe.state.file == 0:
                continue

            filename = lpe_filename(line_program, lpe.state.file)
            if lpe.state.address not in dwarf_loc_map.keys():
                dwarf_loc_map[lpe.state.address] = set()
            dwarf_loc_map[lpe.state.address].add('%s:%d'%(filename, lpe.state.line))

    def lpe_filename(line_program, file_index):
        lp_header = line_program.header
        file_entries = lp_header["file_entry"]

        file_entry = file_entries[file_index - 1]
        dir_index = file_entry["dir_index"]

        if dir_index == 0:
            return file_entry.name.decode()

        directory = lp_header["include_directory"][dir_index - 1]
        return os.path.join(directory, file_entry.name).decode()

    process_file(filename)
    return dwarf_loc_map




def disasm(prog, cs, addr, length):
    offset = addr - prog.text_base
    insts = []
    for inst in prog.disasm_range(cs, addr, length):
        #if not is_semantically_nop(inst):
        insts.append(inst)
    return insts

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
        if ( section.name.startswith(".rel") and \
             ( ("data" in section.name) or \
               section.name.endswith(".dyn") or \
               section.name.endswith('.init_array') or \
               section.name.endswith('.fini_array') ) ) or \
               section.name in ['.rela.plt'] or \
               section.name in ['.rel.plt']:

            for relocation in section.iter_relocations():
                addr = relocation['r_offset']
                t = describe_reloc_type(relocation['r_info_type'], elf)
                sz = get_reloc_bytesize(t)
                is_got = get_reloc_gotoff(t)
                relocs[addr] = (sz, is_got, t)

    return relocs

def get_reloc_symbs(elf, sec_name = '.symtab'):
    names = {}
    dynsym = elf.get_section_by_name(sec_name)#('.dynsym')
    for symb in dynsym.iter_symbols():
        if symb['st_shndx'] != 'SHN_UNDEF':
            addr = symb['st_value']
            name = symb.name
            size = symb['st_size']
            if addr != 0 and len(name) > 0:
                if name in names:
                    names[name].append((addr, size))
                else:
                    names[name] = [(addr, size)]
    return names

class NormalizeGT:
    def __init__(self, bin_path, asm_dir, reloc_file='', build_path=''):
        self.bin_path = bin_path
        self.asm_dir = asm_dir
        self.build_path = build_path
        self.reloc_file = reloc_file
        #self.ex_parser = ATTExParser()

        self.collect_loc_candidates()
        f = open(self.bin_path, 'rb')

        self.elf = ELFFile(f)

        if self.elf.get_section_by_name('.got.plt'):
            self.got_addr = self.elf.get_section_by_name('.got.plt')['sh_addr']
        else:
            self.got_addr = self.elf.get_section_by_name('.got')['sh_addr']

        if reloc_file:
            with open(reloc_file, 'rb') as fp:
                reloc_elf = ELFFile(fp)
                self.relocs = get_reloc(reloc_elf)
        else:
            self.relocs = get_reloc(self.elf)
        self.symbs = get_reloc_symbs(self.elf)

        self.text = self.elf.get_section_by_name(".text")
        self.text_base = self.text.header["sh_addr"]

        if self.elf['e_machine'] in  ('EM_X86_64'):
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        self.cs.detail = True
        self.cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        disassembly = self.cs.disasm(self.text.data(), self.text_base)

        self.comp_gen = CompGen(got_addr = self.got_addr)

        self.instructions = {}  # address : instruction
        for instruction in disassembly:
            self.instructions[instruction.address] = instruction

        self.instruction_addrs = list(self.instructions.keys())
        self.instruction_addrs.sort()

        self.prog = Program(self.elf, self.cs, asm_path=asm_dir)

        self.match_src_to_bin()


    def is_semantically_nop(self, inst):
        if isinstance(inst, capstone.CsInsn):
            mnemonic = inst.mnemonic
            operand_list = inst.op_str.split(', ')
        elif isinstance(inst, AsmInst):
            mnemonic = inst.opcode
            operand_list = inst.operand_list

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


    def get_section(self, addr):
        for section in self.elf.iter_sections():
            sec_addr = section['sh_addr']
            sec_size = section['sh_size']
            if sec_addr <= addr and addr < sec_addr + sec_size:
                return section
        return None


    def get_int(self, addr, sz = 4):
        section = self.get_section(addr)
        if not section:
            return 0
        base = section['sh_addr']
        offset = addr - base
        data = section.data()
        data = data[offset:offset + sz]
        if sz == 4:
            data = data.ljust(4, b'\x00')
            return struct.unpack("<I", data)[0]
        elif sz == 8:
            data = data.ljust(8, b'\x00')
            return struct.unpack("<Q", data)[0]


    def update_table(self, addr, comp_data, asm_path):
        for line, idx in comp_data.members:
            directive = line.split()[0]
            if directive in ['.long']:
                sz = 4
            elif directive in ['.quad']:
                sz = 8
            else:
                assert False, 'Unsupported jump table entries'

            value = self.get_int(addr, sz)

            label_dict = {comp_data.label:comp_data.addr}
            data = self.comp_gen.get_data(addr, asm_path, line, idx, value, label_dict)
            self.prog.Data[addr] = data
            #component = self.comp_gen.get_data_components(line.split()[1], value, label_dict)
            #self.prog.Data[addr] = Data(addr, component, asm_path, idx+1, line)

            addr += sz


    def update_data(self, addr, comp_data, asm_path):
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

            expr = ' '.join(line.split()[1:])
            if sz in [4,8] and re.search('.[+|-]', expr):
                value = self.get_int(addr, sz)

                #if '@GOTOFF' in line:
                #    value += self.got_addr

                data = self.comp_gen.get_data(addr, asm_path, line, idx , value)
                self.prog.Data[addr] = data
                #component = self.comp_gen.get_data_components(expr, value)
                #self.prog.Data[addr] = Data(addr, component, asm_path, idx+1, directive+' '+ expr)

            addr += sz

    def update_labels(self, func_info, factors, asm_file): #label_dict, jmptbls, factors):
        target_addr = factors.value - factors.num
        jmp_list = []
        for label in factors.labels:
            if label == '_GLOBAL_OFFSET_TABLE_':
                continue

            if '@GOT' in label and '@GOTPCREL' not in label:
                label = label.split('@')[0]

            if label in asm_file.composite_data and not asm_file.composite_data[label].addr:
                asm_file.composite_data[label].set_addr(target_addr)

            if label in asm_file.jmp_dict:
                asm_file.jmp_dict[label].set_addr(target_addr)
                jmp_list.append((label, target_addr, len(asm_file.jmp_dict[label].members)))

            if label in asm_file.str_dict:
                asm_file.str_dict[label].set_addr(target_addr)

        return jmp_list


    def get_objdump(self):
        temp_file = "/tmp/xx" + self.bin_path.replace('/','_')
        os.system("objdump -t -f %s | grep \"F .text\" | sort > %s" % (self.bin_path, temp_file))

        funcs = []
        with open(temp_file) as fp:
            lines = fp.readlines()
            for line in lines:
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

        os.unlink(temp_file)

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
        self.instruction_addrs.sort()


    def match_src_to_bin(self):

        self.bin2src_dict = {}
        self.composite_data = dict()
        self.jmp_table_dict = dict()

        debug_loc_paths = {}
        src_files = {}

        #result = {}
        self.dwarf_loc = get_dwarf_loc(self.bin_path)

        funcs = self.get_objdump()   # [funcname, address, size] list
        for func_info in funcs:
            fname, faddress, fsize = func_info

            if '__x86.get_pc_thunk' in fname:
                continue

            '''
            Handle weird padding bytes
            '''
            if faddress not in self.instructions:
                self.update_instr(func_info) #faddress, fsize)

            func_code = self.get_func_code(faddress, fsize)

            asm_file, addressed_asm_list = self.find_match_func(func_code, func_info)

            func_summary = FuncInst(addressed_asm_list, func_info, asm_file.file_path)
            self.bin2src_dict[faddress] = func_summary

            prev_opcode = ''
            for idx, (addr, capstone_insn, asm_token) in enumerate(addressed_asm_list):

                if not asm_token:
                    # nop code might has no relevant assembly code
                    if prev_opcode in ['jmp', 'jmpq', 'jmpl', 'call', 'callq', 'calll', 'ret', 'retq', 'retl', 'halt', 'ud2']:
                        next_addr, _, _ = addressed_asm_list[idx+1]
                        self.prog.aligned_region.update([item for item in range(addr, next_addr)])

                    self.prog.Instrs[addr] = InstType(addr, asm_file.file_path)
                    continue

                prev_opcode = capstone_insn.mnemonic

                instr = self.comp_gen.get_instr(addr, asm_file.file_path, asm_token, capstone_insn)
                self.prog.Instrs[addr] = instr

                # update labels
                jmp_list = []
                if instr.imm and instr.imm.has_label():
                    ret = self.update_labels(func_summary, instr.imm, asm_file)
                    jmp_list.extend(ret)
                if instr.disp and instr.disp.has_label():
                    ret = self.update_labels(func_summary, instr.disp,  asm_file)
                    jmp_list.extend(ret)

                for (label, jmp_base, jmp_size) in jmp_list:
                    func_summary.register_jmp_table(addr, label, jmp_base, jmp_size)


        text_end = self.text.data_size + self.text_base
        prev_end = self.text_base
        unknown_region = set()
        for faddress in sorted(self.bin2src_dict.keys()):
            unknown_region.update(range(prev_end, faddress))
            prev_end = faddress + self.bin2src_dict[faddress].size
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
                # Mnemonic Alias
                ["call", "callw"],
                ["call", "calll"],
                ["call", "callq"],
                ["cbw",  "cbtw"],
                ["cwde", "cwtl"],
                ["cwd",  "cwtd"],
                ["cdq",  "cltd"],
                ["cdqe", "cltq"],
                ["cqo",  "cqto"],
                ["lret", "lretw"],
                ["lret", "lretl"],
                ["leavel", "leave"],
                ["leaveq", "leave"],
                ["loopz",  "loope"],
                ["loopnz", "loopne"],
                ["popf",  "popfw"],
                ["popf",  "popfl"],
                ["popf",  "popfq"],
                ["popfd", "popfl"],
                ["pushf",  "pushfw"],
                ["pushf",  "pushfl"],
                ["pushf",  "pushfq"],
                ["pushfd", "pushfl"],
                ["pusha",  "pushaw"],
                ["pusha",  "pushal"],
                ["repe",  "rep"],
                ["repz",  "rep"],
                ["repnz", "repne"],
                ["ret", "retw"],
                ["ret", "retl"],
                ["ret", "retq"],
                ["salb", "shlb"],
                ["salw", "shlw"],
                ["sall", "shll"],
                ["salq", "shlq"],
                ["smovb", "movsb"],
                ["smovw", "movsw"],
                ["smovl", "movsl"],
                ["smovq", "movsq"],
                ["ud2a",  "ud2"],
                ["verrw", "verr"],
                ["sysret",  "sysretl"],
                ["sysexit", "sysexitl"],
                ["lgdt", "lgdtw"],
                ["lgdt", "lgdtl"],
                ["lgdt", "lgdtq"],
                ["lidt", "lidtw"],
                ["lidt", "lidtl"],
                ["lidt", "lidtq"],
                ["sgdt", "sgdtw"],
                ["sgdt", "sgdtl"],
                ["sgdt", "sgdtq"],
                ["sidt", "sidtw"],
                ["sidt", "sidtl"],
                ["sidt", "sidtq"],
                ["fcmovz",   "fcmove"],
                ["fcmova",   "fcmovnbe"],
                ["fcmovnae", "fcmovb"],
                ["fcmovna",  "fcmovbe"],
                ["fcmovae",  "fcmovnb"],
                ["fcomip",   "fcompi"],
                ["fildq",    "fildll"],
                ["fistpq",   "fistpll"],
                ["fisttpq",  "fisttpll"],
                ["fldcww",   "fldcw"],
                ["fnstcww",  "fnstcw"],
                ["fnstsww",  "fnstsw"],
                ["fucomip",  "fucompi"],
                ["fwait",    "wait"],
                ["fxsaveq",   "fxsave64"],
                ["fxrstorq",  "fxrstor64"],
                ["xsaveq",    "xsave64"],
                ["xrstorq",   "xrstor64"],
                ["xsaveoptq", "xsaveopt64"],
                ["xrstorsq",  "xrstors64"],
                ["xsavecq",   "xsavec64"],
                ["xsavesq",   "xsaves64"],
                # findings
                ['shl', 'sal'],
                ['cmovael', 'cmovnb'],
                ['cmovbq', 'cmovc'],
                ['retq', 'rep ret'],
                ['retl', 'rep ret'],
                # assembler optimization
                ['leaq', 'movq'],
                ['leal', 'movl'],
            ]
            for opcode in opcodes:
                if insn.mnemonic in opcode and asm.opcode in opcode:
                    return True

            if self.check_suffix(insn.mnemonic, asm.opcode):
                return True

            if insn.mnemonic in ['addq'] and asm.opcode in ['subq']:
                if asm.operand_list[0].startswith('$-'):
                    return True

            capstone_bugs = [
                ['movd', 'movq'],
                ['cmovaeq', 'cmovnb'],
                ['cmovaew', 'cmovnb'],
                ['cmovbl', 'cmovc'],
                ['cmovael', 'cmovnc'],
                ['cmovaeq', 'cmovnc'],
            ]
            for opcode in capstone_bugs:
                if insn.mnemonic in opcode and asm.opcode in opcode:
                    return True

        return False

    def check_suffix(self, opcode1, opcode2):
        suffix_list = [('(.*)c$','(.*)b$'),      #setc   -> setb
            ('(.*)z$','(.*)e$'),       #setz   -> sete
            ('(.*)na$','(.*)be$'),     #setna  -> setbe
            ('(.*)nb$','(.*)ae$'),     #setnb  -> setae
            ('(.*)nc$','(.*)ae$'),     #setnc  -> setae
            ('(.*)ng$','(.*)le$'),     #setng  -> setle
            ('(.*)nl$','(.*)ge$'),     #setnl  -> setge
            ('(.*)nz$','(.*)ne$'),     #setnl  -> setge
            ('(.*)pe$','(.*)p$'),      #setpe  -> setp
            ('(.*)po$','(.*)np$'),     #setpo  -> setnp
            ('(.*)nae$','(.*)b$'),     #setnae -> setb
            ('(.*)nbe$','(.*)a$'),     #setnbe -> seta
            ('(.*)nge$','(.*)l$'),     #setnbe -> seta
            ('(.*)nle$','(.*)g$')]     #setnle -> setg
        for (suff1, suff2) in suffix_list:
            rex = suff1+'|'+suff2
            if re.search(rex, opcode1) and re.search(rex,opcode2):
                if re.search(suff1, opcode1): tmp1 = re.findall(suff1, opcode1)[0]
                else: tmp1 = re.findall(suff2, opcode1)[0]
                if re.search(suff1, opcode2): tmp2 = re.findall(suff1, opcode2)[0]
                else: tmp2 = re.findall(suff2, opcode2)[0]
                if tmp1 == tmp2:
                    return True
        return False

    def assem_addr_map(self, func_code, asm_token_list, candidate_len, debug=False):

        addressed_asm_list = []
        idx = 0
        for bin_idx, bin_asm in enumerate(func_code):
            if idx >= len(asm_token_list):
                if self.is_semantically_nop(bin_asm):
                    addressed_asm_list.append((bin_asm.address, bin_asm, ''))
                    continue
                return []
            asm_token = asm_token_list[idx]

            if bin_asm.address in self.dwarf_loc:
                dwarf_set1 = self.dwarf_loc[bin_asm.address]
                dwarf_set2 = set()
                while isinstance(asm_token, LocInfo):
                    dwarf_set2.add( '%s:%d'%(asm_token.path, asm_token.idx))
                    idx += 1
                    asm_token = asm_token_list[idx]
                #give exception for a first debug info since some debug info is related to prev func
                #in case of weak symbols, multiple debug info could be merged.
                #ex) {'xercesc/dom/DOMNodeImpl.hpp:271', './xercesc/dom/impl/DOMNodeImpl.hpp:271'}
                if dwarf_set2 - dwarf_set1:
                    #clang might eliminate file path..
                    new_dwarf_set1 = set()
                    for debug_str in dwarf_set1:
                        file_path, no = debug_str.split(':')
                        file_name = os.path.basename(file_path)
                        new_dwarf_set1.add('%s:%s'%(file_name, no))

                    new_dwarf_set2 = set()
                    for debug_str in dwarf_set2:
                        file_path, no = debug_str.split(':')
                        file_name = os.path.basename(file_path)
                        new_dwarf_set2.add('%s:%s'%(file_name, no))

                    if new_dwarf_set2 - new_dwarf_set1:
                        if (self.is_semantically_nop(bin_asm) and
                            func_code[bin_idx+1].address in self.dwarf_loc):
                            dwarf_set3 = self.dwarf_loc[func_code[bin_idx+1].address]
                            for debug_str in dwarf_set3:
                                file_path, no = debug_str.split(':')
                                file_name = os.path.basename(file_path)
                                new_dwarf_set1.add('%s:%s'%(file_name, no))
                            if new_dwarf_set2 - new_dwarf_set1:
                                return []
                            else:
                                pass
                        else:
                            return []

            if isinstance(asm_token, LocInfo):
                # nop code might not have debug info
                if self.is_semantically_nop(bin_asm):
                    addressed_asm_list.append((bin_asm.address, bin_asm, ''))
                    continue
                elif debug:
                    # some debug info might be omitted
                    while isinstance(asm_token, LocInfo):
                        idx += 1
                        asm_token = asm_token_list[idx]
                    pass
                else:
                    return []

            if self.is_semantically_nop(bin_asm):
                #.align might cause nop code
                if self.is_semantically_nop(asm_token):
                    addressed_asm_list.append((bin_asm.address, bin_asm, asm_token))
                else:
                    addressed_asm_list.append((bin_asm.address, bin_asm, ''))
                    continue
            elif asm_token.opcode == bin_asm.mnemonic:
                addressed_asm_list.append((bin_asm.address, bin_asm, asm_token))
            #capstone couldn't properly handle notrack instruction
            elif len(asm_token.opcode.split()) == 2 and (
                    asm_token.opcode.split()[0] == 'notrack' and
                    asm_token.opcode.split()[1].startswith('jmp') and
                    bin_asm.mnemonic.startswith('jmp')):
                addressed_asm_list.append((bin_asm.address, bin_asm, asm_token))
            elif self.is_semantically_same(bin_asm, asm_token):
                addressed_asm_list.append((bin_asm.address, bin_asm, asm_token))
            else:
                if candidate_len > 1:
                    if debug:
                        pass
                    return []
                print(bin_asm)
                print('%s %s'%(asm_token.opcode, ' '.join(asm_token.operand_list)))
                addressed_asm_list.append((bin_asm.address, bin_asm, asm_token))
                #return []
                #assert False, 'Unexpacted instruction sequence'
            idx += 1

        if idx < len(asm_token_list):
            for idx2 in range(idx, len(asm_token_list)):
                if not isinstance(asm_token_list[idx2], LocInfo):
                    #assert False, 'Unexpacted instruction sequence'
                    return []

        return addressed_asm_list

    def find_match_func(self, func_code, func_info):

        fname, faddress, fsize = func_info
        if not self.has_func_assem_file(fname):
            return None

        ret = []
        candidate_list = self.get_assem_file(fname)
        candidate_len = len(candidate_list)
        for asm_file in candidate_list:
            asm_basename = os.path.basename(asm_file.file_path)
            if asm_basename in ['base32-basenc.s', 'base64-basenc.s', 'basenc-basenc.s',
                        'b2sum-b2sum.s', 'cksum-b2sum.s', 'b2sum-blake2b-ref.s', 'cksum-blake2b-ref.s',
                        'b2sum-digest.s', 'cksum-digest.s', 'md5sum-digest.s', 'sha1sum-digest.s',
                        'sha224sum-digest.s', 'sha256sum-digest.s', 'sha384sum-digest.s',
                        'sha512sum-digest.s', 'sum-digest.s', 'cksum-sum.s', 'sum-sum.s']:
                if asm_basename.split('-')[0] != os.path.basename(self.bin_path):
                    continue

            if os.path.basename(asm_file.file_path) in ['src_sha224sum-md5sum.s']:
                if os.path.basename(self.bin_path) in ['sha512sum', 'sha256sum', 'sha384sum']:
                    continue
            if os.path.basename(asm_file.file_path) in ['src_sha256sum-md5sum.s']:
                if os.path.basename(self.bin_path) in ['sha512sum', 'sha224sum', 'sha384sum']:
                    continue
            if os.path.basename(asm_file.file_path) in ['src_sha384sum-md5sum.s']:
                if os.path.basename(self.bin_path) in ['sha512sum', 'sha224sum', 'sha256sum']:
                    continue
            if os.path.basename(asm_file.file_path) in ['src_sha512sum-md5sum.s']:
                if os.path.basename(self.bin_path) in ['sha224sum', 'sha256sum', 'sha384sum']:
                    continue
            if 'usable_st_size' in fname:
                '''
                    grep  '^usable_st_size:'  coreutils-8.30/x64/clang/nopie/o1-bfd/src/* -A 10 | grep orl
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/dd.s-	orl	24(%rdi), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/head.s-	orl	24(%rdi), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/od.s-	orl	24(%rdi), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/shuf.s-	orl	24(%rdi), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/split.s-	orl	in_stat_buf+24(%rip), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/tail.s-	orl	24(%rdi), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/truncate.s-	orl	24(%rdi), %eax
                    coreutils-8.30/x64/clang/nopie/o1-bfd/src/wc.s-	orl	24(%rdi), %eax
                '''
                if os.path.basename(asm_file.file_path) in ['dd.s', 'head.s', 'od.s', 'shuf.s', 'tail.s', 'truncate.s', 'wc.s']:
                    if os.path.basename(self.bin_path) in ['split']:
                        continue
                if os.path.basename(asm_file.file_path) in ['split.s']:
                    if os.path.basename(self.bin_path) in  ['dd', 'head', 'od', 'shuf', 'tail', 'truncate', 'wc']:
                        continue


            #asm_inst_list = [line for line in asm_file.func_dict[fname] if isinstance(line, AsmInst)]
            #addressed_asm_list = self.assem_addr_map(func_code, asm_inst_list, candidate_len)
            addressed_asm_list = self.assem_addr_map(func_code, asm_file.func_dict[fname], candidate_len)

            if not addressed_asm_list:
                continue
            ret.append((asm_file, addressed_asm_list))


        if not ret:
            # debug info might be omitted.
            # we give some exception to assembly matching.
            for asm_file in candidate_list:
                addressed_asm_list = self.assem_addr_map(func_code, asm_file.func_dict[fname], candidate_len, True)

                if addressed_asm_list:
                    ret.append((asm_file, addressed_asm_list))

            assert len(ret) in [1,2], 'No matched assembly code'


        asm_file, addressed_asm_list = ret[0]
        asm_file.visited_func.add(fname)

        return asm_file, addressed_asm_list

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
            print("Disassembly failed.")
            exit()

    def get_src_files(self, src_files, loc_candidates):
        for loc_path, _ in loc_candidates:
            if loc_path not in src_files.keys():
                if self.build_path:
                    loc_path_full = os.path.join(self.build_path, loc_path[1:])
                    f = open(loc_path_full, errors='ignore')
                    src_files[loc_path] = f.read()
                else:
                    loc_path_full = os.path.join(self.asm_dir, loc_path[1:])
                    f = open(loc_path_full, errors='ignore')
                    src_files[loc_path] = f.read()
        return src_files


    def get_src_paths(self):
        srcs = []
        for i in range(20):
            t = "*/" * i
            srcs += glob.glob(self.asm_dir + t + "*.s")

        # give a first priority to a main source code
        main_src = '%s/src/%s.s'%(self.asm_dir, os.path.basename(self.bin_path))
        if main_src in srcs:
            srcs.remove(main_src)
            srcs.insert(0, main_src)

        return srcs

    def has_func_assem_file(self, func_name):
        return func_name in self._func_map

    def get_assem_file(self, func_name):
        ret = []
        for asm_path in self._func_map[func_name]:
            #ignored referred assembly file
            #since local function can be defined twice
            # _Z41__static_initialization in 483.xalancbmk
            if func_name in self.asm_file_dict[asm_path].visited_func:
                pass
            else:
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


    def normalize_data(self):
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
                        #if symbol size is zero we ignore it
                        if self.symbs[label][0][1] == 0:
                            continue
                        self.update_data(self.symbs[label][0][0], comp_data, asm_path)
                        visited_label.append(label)
                    #else:
                    #    print('unknown comp data %s:%s'%(asm_path, label))

        comp_set = set(self.prog.Data.keys())
        reloc_set = set(self.relocs)

        if comp_set - reloc_set:
            print(comp_set - reloc_set)

        for asm_path, asm_file in self.asm_file_dict.items():
            for label, comp_data in asm_file.jmp_dict.items():
                if comp_data.addr:
                    self.update_table(comp_data.addr, comp_data, asm_path)
                    visited_label.append(label)

            for label, comp_data in asm_file.str_dict.items():
                if comp_data.addr:
                    self.update_table(comp_data.addr, comp_data, asm_path)
                    visited_label.append(label)


        for addr in self.relocs:

            if addr in self.prog.Data:
                # composite ms || already processed
                continue
            sz, is_got, r_type = self.relocs[addr]
            value = self.get_int(addr, sz)
            #This reloc data is added by linker
            #if value == 0 and r_type in ['R_X86_64_64']:
            #    asm_line = '.quad %s'%(r_type)
            #    pass
            #elif value == 0:
            #    continue
            if r_type in ['R_X86_64_COPY', 'R_X86_64_REX_GOTPCRELX', 'R_386_COPY']:
                continue
            elif r_type in ['R_X86_64_GLOB_DAT', 'R_X86_64_JUMP_SLOT', 'R_386_GLOB_DAT', 'R_386_JUMP_SLOT']:
                label = 'L%x'%(value)
                asm_line = '.long ' + label
            else:
                directive = '.long'
                if value == 0:
                    label = r_type
                else:
                    if is_got:
                        value += self.got_addr
                        label = 'L%x@GOTOFF'%(value)
                    else:
                        label = 'L%x'%(value)
                        if sz == 8: directive = '.quad'

                asm_line = directive + ' ' + label

            data = self.comp_gen.get_data(addr, '',  asm_line, 0, value, r_type = r_type)
            self.prog.Data[addr] = data

    def save(self, save_file):
        with open(save_file, 'wb') as f:
            pickle.dump(self.prog, f)

    def save_func_dict(self, save_file):
        with open(save_file, 'w') as f:
            res = {}
            for key, val in self.bin2src_dict.items():
                func_info = dict()
                func_info['asm_path'] = val.asm_path
                func_info['addr'] = hex(val.addr)
                func_info['inst_addrs'] = [hex(addr) for (addr, _, _) in val.inst_list]
                func_info['jmp_tables'] = []
                for tbl in val.jmp_table_list:
                    func_info['jmp_tables'].append({'inst_addr':hex(tbl['inst_addr']),
                        'label':tbl['label'], 'addr':hex(tbl['addr']), 'size':tbl['size']})

                res[hex(key)] = func_info

            data = json.dumps(res, indent=1)
            #print(re.sub(r',\n\s*([0-9])', r',\1', data), file=f)
            print(re.sub(r',\n\s*"([0-9])', r',"\1', data), file=f)

class FuncSummary:
    def __init__(self, func_inst):
        self.asm_path = func_inst.asm_path
        self.addr = func_inst.addr
        self.inst_addrs = [addr for (addr, _, _) in func_inst.inst_list]
        self.jmp_table_list = func_inst.jmp_table_list



import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_retro')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('asm_dir', type=str)
    parser.add_argument('save_file', type=str)
    parser.add_argument('--reloc', type=str)
    parser.add_argument('--build_path', type=str)
    parser.add_argument('--save_func_dict', type=str)
    args = parser.parse_args()

    gt = NormalizeGT(args.bin_path, args.asm_dir, args.reloc, args.build_path)
    gt.normalize_data()

    gt.save(args.save_file)

    if args.save_func_dict:
        gt.save_func_dict(args.save_func_dict)

