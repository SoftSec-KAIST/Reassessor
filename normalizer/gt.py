import re
import capstone
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
import sys
import os
import pickle
import glob, json
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.relocation import RelocationSection
from collections import defaultdict

from lib.asm_types import Program, Component, Instr, Data, LblTy, Label
from lib.parser import ATTExParser, FactorList
from normalizer.asmfile import AsmFileInfo, LocInfo, AsmInst
from lib.utils import load_elf, get_int

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

class NormalizeGT:
    def __init__(self, bin_path, asm_dir, work_dir='/data2/benchmark'):
        self.bin_path = bin_path
        self.asm_dir = asm_dir
        self.work_dir = work_dir
        self.ex_parser = ATTExParser()

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


        print('match_src_to_bin')
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


    def parse_components(self, insn, asm_info, func_info, asm_file):
        operands = insn.operands
        components = []


        asm_operands = asm_info.operand_list

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
                    print('%s %s'%(asm_info.opcode, ' '.join(asm_info.operand_list)))
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

            elif operand.type == X86_OP_MEM:
                is_pcrel = False
                value = operand.mem.disp
                if operand.mem.base == X86_REG_RIP:
                    is_pcrel = True

            else:
                continue

            if is_pcrel and not (insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL)):
                value += insn.address + insn.size
            elif '@GOTOFF' in op_str:
                value += self.got_addr

            if op_str == "_GLOBAL_OFFSET_TABLE_":
                gotoff = self.got_addr - insn.address
            else:
                gotoff = 0

            factors = FactorList(self.ex_parser.parse(op_str), value, gotoff=gotoff)

            if factors.has_label():
                components.append(Component(factors.get_terms(), value, is_pcrel, factors.get_str()))
            else:
                components.append(Component())

            if factors.has_label():
                self.update_labels(func_info, factors, asm_file)

        return components


    def update_table(self, addr, comp_data, asm_path):
        for line, idx in comp_data.members:
            directive = line.split()[0]
            if directive in ['.long']:
                sz = 4
            elif directive in ['.quad']:
                sz = 8
            else:
                assert False, 'Unsupported jump table entries'

            value = get_int(self.elf, addr, sz)

            factors = FactorList(self.ex_parser.parse(line.split()[1]), value)
            component = Component(factors.get_table_terms(comp_data), value,  False, self.got_addr)
            self.prog.Data[addr] = Data(addr, component, asm_path, idx+1, line)

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
                value = get_int(self.elf, addr, sz)
                factors = FactorList(self.ex_parser.parse(expr), value)

                if '@GOTOFF' in line:
                    value += self.got_addr

                component = Component(factors.get_terms(), value,  False, self.got_addr)
                self.prog.Data[addr] = Data(addr, component, asm_path, idx+1, directive+' '+ expr)

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

            self.bin2src_dict[faddress] = FuncInst(addressed_asm_list, func_info, asm_file.file_path)
            for addr, capstone_insn, asm in addressed_asm_list:

                components = self.parse_components(capstone_insn, asm, self.bin2src_dict[faddress], asm_file)

                for com in components:
                    lbls = com.get_labels()
                    if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                        com.Value += self.got_address

                self.prog.Instrs[addr] = Instr(addr, components, asm_file.file_path, asm)


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
                if asm.operand_list[0].startswith('$-'):
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

            if bin_asm.address in self.dwarf_loc:
                dwarf_set1 = self.dwarf_loc[bin_asm.address]
                dwarf_set2 = set()
                while isinstance(asm, LocInfo):
                    dwarf_set2.add( '%s:%d'%(asm.path, asm.idx))
                    idx += 1
                    asm = asm_list[idx]
                #give exception for a first debug info since some debug info is related to prev func
                #in case of weak symbols, multiple debug info could be merged.
                #ex) {'xercesc/dom/DOMNodeImpl.hpp:271', './xercesc/dom/impl/DOMNodeImpl.hpp:271'}
                if dwarf_set2 - dwarf_set1:
                    #if 0 == len(addressed_asm_list) and 0 == len(dwarf_set2 - dwarf_set1):
                    #    pass
                    #else:
                    return []

            if isinstance(asm, LocInfo):
                return []

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
                print('%s %s'%(asm.opcode, ' '.join(asm.operand_list)))
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

        ret = []
        candidate_list = self.get_assem_file(fname)
        candidate_len = len(candidate_list)
        for asm_file in candidate_list:

            #asm_inst_list = [line for line in asm_file.func_dict[fname] if isinstance(line, AsmInst)]
            #addressed_asm_list = self.assem_addr_map(func_code, asm_inst_list, candidate_len)
            addressed_asm_list = self.assem_addr_map(func_code, asm_file.func_dict[fname], candidate_len)

            if not addressed_asm_list:
                continue
            ret.append((asm_file, addressed_asm_list))


        if not ret:
            import pdb
            pdb.set_trace()
            for asm_file in candidate_list:
                addressed_asm_list = self.assem_addr_map(func_code, asm_file.func_dict[fname], candidate_len)
            assert False, 'No matched assembly code'


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
            #ignored referred assembly file
            #since local function can be defined twice???
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
                        self.update_data(self.symbs[label][0], comp_data, asm_path)
                        visited_label.append(label)
                    #else:
                    #    print('unknown comp data %s:%s'%(asm_path, label))

        comp_set = set(self.prog.Data.keys())
        reloc_set = set(self.relocs)

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
                lbl = Label("L%X@GOTOFF"%(value), LblTy.GOTOFF, value)
            else:
                lbl = Label("L%X"%(value), LblTy.LABEL, value)

            if sz == 4:
                directive = '.long'
            elif sz == 8:
                directive = '.quad'
            else:
                directive = None

            component = Component([lbl], value)
            # If we already have addr, it means it should be a jump table
            if addr not in self.prog.Data:
                self.prog.Data[addr] = Data(addr, component, '', 0, directive + ' ' + lbl.Name)


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_retro')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('asm_dir', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    gt = NormalizeGT(args.bin_path, args.asm_dir)
    gt.normalize_data()

    with open(args.save_file, 'wb') as f:
        pickle.dump(gt.prog, f)

