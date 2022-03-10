from abc import abstractmethod
import capstone
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
from collections import namedtuple

from lib.asm_types import Program, Component, Instr, Data, LblTy
from lib.utils import load_elf, get_disassembler, get_arch
from lib.parser import FactorList, ATTExParser, IntelExParser, AsmTokenizer, ReasmInst, ReasmData


AddrAsm = namedtuple('AddrAsm', ['addr', 'asm_line', 'idx', 'type'])

class NormalizeTool:
    def __init__(self, bin_path, reassem_path, map_func, label_to_addr_func, syntax = capstone.CS_OPT_SYNTAX_ATT):
        self.bin_path = bin_path
        self.reassem_path = reassem_path

        self.elf = load_elf(self.bin_path)

        self.cs = get_disassembler(get_arch(self.elf))
        self.cs.detail = True
        self.cs.syntax = syntax

        self.prog = Program(self.elf, self.cs)

        self.relocs = self.get_reloc_symbs()

        self.mapper(map_func)

        self.label_to_addr = label_to_addr_func

        self.got_addr = self.elf.get_section_by_name('.got.plt')['sh_addr']
    def mapper(self, map_func):

        tokenizer = AsmTokenizer(self.cs.syntax)
        addressed_lines = map_func(self.reassem_path, tokenizer)

        self.addressed_asms = [asm for asm in addressed_lines if isinstance(asm, ReasmInst)]
        self.addressed_data = [asm for asm in addressed_lines if isinstance(asm, ReasmData)]
        '''
        for addr_asm in addressed_lines:

            if addr_asm.type == 'data':
                if addr_asm.asm_line.startswith('.quad'):
                    sz = 8
                elif addr_asm.asm_line.startswith('.long'):
                    sz = 4
                else:
                    raise
                self.addressed_data.append((addr_asm.addr, addr_asm.asm_line, sz, addr_asm.idx))
            elif addr_asm.type == 'text':
                asm_token = tokenizer.parse(addr_asm.asm_line, addr_asm.addr, addr_asm.idx)
                self.addressed_asms.append(asm_token)
                #tokens = tokenzer.
                #if self.cs.syntax == capstone.CS_OPT_SYNTAX_ATT:
                #    tokens = parse_att_asm_line(addr_asm.asm_line)
                #else:
                #    tokens = parse_intel_asm_line(addr_asm.asm_line)

                #if tokens:
                #    addressed_asms.append((addr_asm.addr, tokens, addr_asm.idx))

            else:
                pass

        '''


    def get_reloc_symbs(self):
        names = {}

        dynsym = self.elf.get_section_by_name('.dynsym')
        for symb in dynsym.iter_symbols():
            names[symb.name] = symb['st_value']
        return names

    def parse_components(self, insn, asm_token):
        operands = insn.operands
        components = []
        if self.cs.syntax == capstone.CS_OPT_SYNTAX_ATT:
            parser = ATTExParser()
        elif self.cs.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            parser = IntelExParser()


        if asm_token.opcode.startswith('nop'):
            components.append(Component())

        for idx, operand in enumerate(operands):

            if len(asm_token.operand_list) <= idx:
                print(insn)
                break

            op_str = asm_token.operand_list[idx]
            if operand.type == X86_OP_REG:
                components.append(Component())
                continue
            elif operand.type == X86_OP_IMM:
                is_pcrel = False
                if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                    is_pcrel = True

                value = operand.imm

            elif operand.type == X86_OP_MEM:
                is_pcrel = False
                if operand.mem.base == X86_REG_RIP:
                    value = insn.address + insn.size + operand.mem.disp
                    is_pcrel = True
                else:
                    value = operand.mem.disp

            else:
                continue


            if '@GOTOFF' in op_str:
                value += self.got_addr

            if '_GLOBAL_OFFSET_TABLE_' in op_str:
                gotoff = self.got_addr - insn.address
            else:
                gotoff = 0

            factors = FactorList(parser.parse(op_str), value, self.label_to_addr, gotoff)

            if factors.has_label():
                components.append(Component(factors.get_terms(), value, is_pcrel, factors.get_str()))
            else:
                components.append(Component())



        if self.cs.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            components.reverse()
        return components



    def normalize_inst(self):
        text_start = self.prog.text_base
        text_end = self.prog.text_base + len(self.prog.text_data)

        skip = -1
        #for i, (addr, tokens, line) in enumerate(self.addressed_asms):
        for idx, asm_token in enumerate(self.addressed_asms):
            if idx <= skip:
                continue
            addr = asm_token.addr
            if addr < text_start:
                continue
            elif addr >= text_end:
                continue

            if idx == len(self.addressed_asms) - 1:
                inst = self.prog.disasm(self.cs, addr, 15)
            else:
                next_addr = self.addressed_asms[idx+1].addr
                if addr == next_addr:
                    continue
                try:
                    inst = self.prog.disasm(self.cs, addr, next_addr - addr)
                except IndexError:
                    #handle ddisasm: 'nopw   %cs:0x0(%rax,%rax,1)' -> 'nop'
                    if asm_token.opcode == 'nop':
                        for j in range(idx+1, idx+16):
                            next_addr = self.addressed_asms[j].addr
                            if self.addressed_asms[j].opcode!= 'nop':
                                break
                            else:
                                skip = j
                        inst = self.prog.disasm(self.cs, addr, next_addr - addr)
                    else:
                        raise SyntaxError('Unexpected byte code')

            components = self.parse_components(inst, asm_token)

            for c in components:
                lbls = c.get_labels()
                if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                    c.Value += self.got_addr
            self.prog.Instrs[addr] = Instr(addr, components, self.reassem_path, asm_token.idx)

            #print('Inst:', hex(addr))

    def normalize_data(self):
        #for addr, token, size, line in self.addressed_data:
        for reasm_data in self.addressed_data:
            #print(token)

            factors = self.parse_data_expr(reasm_data.expr)

            #factors = FactorList(parser.parse(op_str), value, self.label_to_addr)

            component = Component(factors.get_terms(), reloc_sym = factors.get_str())
            self.prog.Data[reasm_data.addr] = Data(reasm_data.addr, component, self.reassem_path, reasm_data.asm_line)
            #print('Data:', hex(addr))

    def parse_data_expr(self, op_str):

        if self.cs.syntax == capstone.CS_OPT_SYNTAX_ATT:
            parser = ATTExParser()
        elif self.cs.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            parser = IntelExParser()

        value = 0
        result = FactorList(parser.parse(op_str), value, self.label_to_addr)

        return result



    @abstractmethod
    def address_src_file(self):
        pass


