from abc import abstractmethod
import re
import capstone
from capstone.x86 import *
import sys
import os

from lib.asm_types import *
from lib.utils import *

# FIXME: clean up later
RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')

DATA_DIRECTIVE = ['.byte', '.asciz', '.quad', '.ascii', '.long', '.short']
SKIP_DIRECTIVE = ['.align', '.globl', '.type']

REGISTERS = ['RIP', 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
        'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D',
        'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP']

def has_label(term, relocs):
    if not term: return False
    return re.search('^(\$*[\._a-zA-Z])', term) is not None

def parse_att_asm_line(line):
    if line.lower().startswith("nop"):
        return []

    prev = line.split(',')[0]
    opcode_len = 1
    if prev.split()[0].lower().startswith('rep'):
        opcode_len = 2
    opcode = ' '.join(prev.split()[:opcode_len])
    arg_str = ' '.join(line.split()[opcode_len:])
    ret = [opcode, []]

    token = ''
    lpar = False
    for char in arg_str:
        if lpar:
            token += char
            if char == ')':
                lpar = False
            continue
        if char == ',':
            ret[1].append(token)
            token = ''
            continue
        if char == ' ':
            continue

        token += char
        if char == '(':
            lpar = True
    if token:
        ret[1].append(token)

    return ret

class Factor:
    def __init__(self, op, data):
        self.op = op
        self.data = data

    def get_str(self):
        if self.op == '+':
            return self.data
        elif self.op == '-':
            return self.op + self.data

        raise SyntaxError('Unexpected operator')

def get_addr_from_label(label, ):
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



class FactorList:
    def __init__(self, factors, value, _label_to_addr=None, gotoff=0):
        self.labels = []
        self.num = 0
        self.value = value
        self._label_to_addr = _label_to_addr
        self.gotoff = gotoff
        for factor in factors:
            if factor.data.isdigit() or factor.data.startswith('0x'):
                self.num += eval(factor.get_str())
            else:
                self.labels.append(factor.get_str())

    def has_label(self):
        return len(self.labels) > 0

    def get_str(self):
        ret = ''
        for label in self.labels:
            if ret and label[0] != '-':
                ret += '+'
            ret += label
        if self.num > 0:
            ret += '+%s'%(hex(self.num))
        elif self.num < 0:
            ret += '%s'%(hex(self.num))

        return ret

    def label_to_addr(self, label):
        if self._label_to_addr is None:
            return 0
        if isinstance(self._label_to_addr, dict):
            if label in self._label_to_addr:
                return self._label_to_addr[label]
            else:
                return 0
        return self._label_to_addr(label)

    def get_terms(self):
        result = []

        for label in self.labels:
            if '_GLOBAL_OFFSET_TABLE_' in label:
                addr = self.gotoff
            elif '@GOTOFF' in label:
                addr = self.label_to_addr(label.split('@GOTOFF')[0])
                label_type = LblTy.GOTOFF
            else:
                if label[0] == '-':
                    addr = self.label_to_addr(label[1:])
                else:
                    addr = self.label_to_addr(label)
                label_type = LblTy.LABEL

            if addr == 0:
                if len(self.labels) > 1:
                    raise SyntaxError('Unsolved label')
                addr = self.value - self.num

            lbl = Label(label, label_type, addr)
            result.append(lbl)
        if self.num:
            return result + [self.num]
        return result

    def get_table_terms(self, base_label):

        assert len(self.labels) == 2, 'This is not type 7'
        assert self.num == 0, 'This is not type 7'
        assert self.labels[1][1:] == base_label.label, 'This is incorrect jump table base'

        addr1 = (self.value + base_label.addr) & 0xffffffff
        lbl1 = Label(self.labels[0], LblTy.LABEL, addr1)
        lbl2 = Label(self.labels[1], LblTy.LABEL, base_label.addr)

        return [lbl1, lbl2]


class ExParser:
    def __init__(self):
        self.line = ''
        self.current = ''

    def parse(self, expr):
        self.line = self._strip(expr)
        result =  self._exp()
        if self.line != '':
            raise SyntaxError('Unexpected character after expression: ' + self.line)
        return result

    def _is_next(self, regexp):
        m = re.match(r'\s*' + regexp + r'\s*', self.line)
        if m:
            self.current = m.group().strip()
            self.line = self.line[m.end():]
            return True
        return False

    @abstractmethod
    def _strip(self):
        pass

    @abstractmethod
    def _exp(self):
        pass

    @abstractmethod
    def _term(self):
        pass

    @abstractmethod
    def _factor(self):
        pass

class ATTExParser(ExParser):
    def _strip(self, expr):
        if re.search('.*\(.*\)', expr):
            expr = re.findall('(.*)\(.*\)', expr)[0]
        elif expr[0] == '%':
            return ''
        elif re.search ('%fs:.*', expr):
            return ''
        #remove offset directive
        return expr.replace('$','')

    def _exp(self):
        result = []
        factor = self._factor()
        if factor.data:
            result.append(factor)

        while self._is_next(r'[-+]'):
            op = self.current
            factor = self._factor()
            if factor.data:
                result.append(Factor(op, factor.data))

        return result

    def _term(self):
        pass

    def _factor(self):
        if self._is_next(r'-'):
            factor = self._factor()
            if factor.op == '+':
                return Factor('-', factor.data)
        elif self._is_next(r'[_.a-zA-Z0-9@]*'):
            return Factor('+', self.current)


        raise SyntaxError('Unexpect syntax' + self.line)


class IntelExParser(ExParser):
    def _strip(self, expr):
        if re.search('.* PTR \[.*\]', expr):
            expr = re.findall('.* PTR \[(.*)\]', expr)[0]
        elif re.search('OFFSET .*', expr):
            expr = re.findall('OFFSET (.*)', expr)[0]
        elif re.search ('.* PTR FS:.*', expr):
            return ''
        return expr

    def _exp(self):
        result = []
        factor = self._term()
        if factor.data:
            result.append(factor)

        while self._is_next(r'[-+]'):
            op = self.current
            factor = self._term()
            if factor.data:
                result.append(Factor(op, factor.data))

        return result

    def _term(self):
        fact1 = self._factor()
        fact2 = None
        while self._is_next('[*]'):
            fact2 = self._factor()

        if fact2 is None:
            return fact1
        else: # ignore multiply
            return Factor(None, None)

    def _factor(self):
        if self._is_next(r'[_.a-zA-Z0-9@]*'):
            if self.current in REGISTERS: # ignore register
                return Factor(None, None)


            return Factor('+', self.current)

        elif self._is_next(r'-'):
            factor = self._factor()
            if factor.op == '+':
                return Factor('-', factor.data)

        raise SyntaxError('Unexpect syntax' + self.line)



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

        self.addressed_asms, self.addressed_data = map_func(reassem_path)

        self.label_to_addr = label_to_addr_func

        self.got_addr = self.elf.get_section_by_name('.got.plt')['sh_addr']


    def get_reloc_symbs(self):
        names = {}

        dynsym = self.elf.get_section_by_name('.dynsym')
        for symb in dynsym.iter_symbols():
            names[symb.name] = symb['st_value']
        return names

    def parse_components(self, insn, tokens):
        operands = insn.operands
        components = []
        if self.cs.syntax == capstone.CS_OPT_SYNTAX_ATT:
            parser = ATTExParser()
        elif self.cs.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            parser = IntelExParser()


        for idx, operand in enumerate(operands):

            if len(tokens[1]) <= idx:
                print(insn)
                break

            op_str = tokens[1][idx]
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
        for i, (addr, tokens, line) in enumerate(self.addressed_asms):
            if i <= skip:
                continue

            if addr < text_start:
                continue
            elif addr >= text_end:
                continue

            if i == len(self.addressed_asms) - 1:
                inst = self.prog.disasm(self.cs, addr, 15)
            else:
                next_addr, _, _ = self.addressed_asms[i+1]
                if addr == next_addr:
                    continue
                try:
                    inst = self.prog.disasm(self.cs, addr, next_addr - addr)
                except IndexError:
                    #handle ddisasm: 'nopw   %cs:0x0(%rax,%rax,1)' -> 'nop'
                    if tokens[0] == 'nop':
                        for j in range(i+1, i+16):
                            next_addr = self.addressed_asms[j][0]
                            if self.addressed_asms[j][1][0] != 'nop':
                                break
                            else:
                                skip = j
                        inst =self.prog.disasm(self.cs, addr, next_addr - addr)
                    else:
                        raise SyntaxError('Unexpected byte code')

            components = self.parse_components(inst, tokens)

            for c in components:
                lbls = c.get_labels()
                if len(lbls) == 1 and lbls[0].get_type() == LblTy.GOTOFF:
                    c.Value += self.got_addr
            self.prog.Instrs[addr] = Instr(addr, components, self.reassem_path, line)

            #print('Inst:', hex(addr))

    def normalize_data(self):
        for addr, token, size, line in self.addressed_data:
            #print(token)

            factors = self.parse_data_expr(token.strip())

            #factors = FactorList(parser.parse(op_str), value, self.label_to_addr)

            component = Component(factors.get_terms(), reloc_sym = factors.get_str())
            self.prog.Data[addr] = Data(addr, component, self.reassem_path, line)
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


