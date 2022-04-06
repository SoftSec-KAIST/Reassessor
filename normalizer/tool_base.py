from abc import abstractmethod
import capstone
from collections import namedtuple
import pickle
from lib.types import Program, LblTy
from lib.utils import load_elf, get_disassembler, get_arch
from lib.parser import AsmTokenizer, ReasmInst, ReasmData, CompGen


class NormalizeTool:
    def __init__(self, bin_path, reassem_path, map_func, label_to_addr_func, syntax = capstone.CS_OPT_SYNTAX_ATT):
        self.bin_path = bin_path
        self.reassem_path = reassem_path

        self.elf = load_elf(self.bin_path)

        if self.elf.get_section_by_name('.got.plt'):
            self.got_addr = self.elf.get_section_by_name('.got.plt')['sh_addr']
        else:
            self.got_addr = self.elf.get_section_by_name('.got')['sh_addr']

        self.comp_gen = CompGen(label_to_addr = label_to_addr_func, syntax=syntax, got_addr = self.got_addr)

        self.cs = get_disassembler(get_arch(self.elf))
        self.cs.detail = True
        self.cs.syntax = syntax

        self.prog = Program(self.elf, self.cs)

        self.relocs = self.get_reloc_symbs()

        self.mapper(map_func)

        self.label_to_addr = label_to_addr_func


    def mapper(self, map_func):

        tokenizer = AsmTokenizer(self.cs.syntax)
        addressed_lines = map_func(self.reassem_path, tokenizer)

        self.addressed_asms = [asm for asm in addressed_lines if isinstance(asm, ReasmInst)]
        self.addressed_data = [asm for asm in addressed_lines if isinstance(asm, ReasmData)]

    def get_reloc_symbs(self):
        names = {}

        dynsym = self.elf.get_section_by_name('.dynsym')
        for symb in dynsym.iter_symbols():
            names[symb.name] = symb['st_value']
        return names

    def normalize_inst(self):
        text_start = self.prog.text_base
        text_end = self.prog.text_base + len(self.prog.text_data)

        skip = -1
        last_idx = len(self.addressed_asms) - 1
        for idx, asm_token in enumerate(self.addressed_asms):
            if idx <= skip:
                continue
            addr = asm_token.addr
            if addr < text_start:
                continue
            elif addr >= text_end:
                continue

            if idx == len(self.addressed_asms) - 1:
                insn = self.prog.disasm(self.cs, addr, 15)
            else:
                next_addr = self.addressed_asms[idx+1].addr
                if addr == next_addr:
                    continue
                try:
                    insn = self.prog.disasm(self.cs, addr, next_addr - addr)
                except IndexError:
                    #handle ddisasm: 'nopw   %cs:0x0(%rax,%rax,1)' -> 'nop'
                    if asm_token.opcode == 'nop':
                        for j in range(idx+1, idx+16):
                            next_addr = self.addressed_asms[j].addr
                            if self.addressed_asms[j].opcode!= 'nop':
                                break
                            else:
                                skip = j
                            if last_idx == j:
                                next_addr += 1
                                break
                        try:
                            insn = self.prog.disasm(self.cs, addr, next_addr - addr)
                        except IndexError:
                            continue
                    else:
                        # ramblr might emit overwrapped code
                        try:
                            insn = self.prog.disasm(self.cs, addr, addr + 16)
                        except IndexError:
                            import pdb
                            pdb.set_trace()
                            raise SyntaxError('Unexpected byte code')

            instr = self.comp_gen.get_instr(addr, self.reassem_path, asm_token)
            self.prog.Instrs[addr] = instr

            '''
            for c in components:
                lbls = c.get_labels()
                if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                    c.Value += self.got_addr
            self.prog.Instrs[addr] = Instr(addr, components, self.reassem_path, asm_token)
            '''

    def normalize_data(self):
        for reasm_data in self.addressed_data:
            data = self.comp_gen.get_data(reasm_data.addr, self.reassem_path, reasm_data.asm_line, reasm_data.idx)
            self.prog.Data[reasm_data.addr] = data
            #component = self.comp_gen.get_data_components(reasm_data.expr)
            #self.prog.Data[reasm_data.addr] = Data(reasm_data.addr, component, self.reassem_path, reasm_data.idx, reasm_data.asm_line)

    @abstractmethod
    def address_src_file(self):
        pass

    def save(self, save_file):
        with open(save_file, 'wb') as f:
            pickle.dump(self.prog, f)

