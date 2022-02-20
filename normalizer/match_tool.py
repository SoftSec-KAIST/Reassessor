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
    src_inst = line.strip()
    if src_inst.lower().startswith("nop"):
        return []
    if " " in src_inst:
        src_inst = src_inst.split(" ", 1)
        if src_inst[0].startswith("rep"):
            s = src_inst[1].split(" ", 1)
            src_inst[0] += " " + s[0]
            if len(s) > 1:
                src_inst[1] = s[1]
            else:
                src_inst[1] = ''
        src_inst[1] = src_inst[1].split(",")
    else:
        src_inst = [src_inst, []]
    for i in range(len(src_inst[1])):
        src_inst[1][i] = src_inst[1][i].strip()
    return src_inst

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
    def __init__(self, factors, value, label_to_addr):
        self.labels = []
        self.num = 0
        self.value = value
        self.label_to_addr = label_to_addr
        for factor in factors:
            if factor.data.isdigit():
                self.num += eval(factor.get_str())
            else:
                self.labels.append(factor.get_str())

    def has_label(self):
        return len(self.labels) > 0

    def get_terms(self):
        result = []

        for label in self.labels:
            if '@GOTOFF' in label:
                addr = self.label_to_addr(label.split('@GOTOFF')[0])
                label_type = LblTy.GOTOFF
            else:
                addr = self.label_to_addr(label)
                label_type = LblTy.LABEL

            if addr == 0:
                if len(self.labels) > 1:
                    raise SyntaxError('Unsolved label')
                addr = self.value - self.num
                #print('unknown %s + %d: %s'%(label, self.num, hex(addr)))

            lbl = Label(label, label_type, addr)
            result.append(lbl)
        if self.num:
            return result + [self.num]
        return result


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
            elif operand.type == X86_OP_IMM:
                is_pcrel = False
                if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                    is_pcrel = True

                value = operand.imm
                if '@GOTOFF' in op_str:
                    value += self.got_addr
                res = FactorList(parser.parse(op_str), value, self.label_to_addr)

                if res.has_label():
                    components.append(Component(res.get_terms(), value, is_pcrel))
                else:
                    components.append(Component())

            elif operand.type == X86_OP_MEM:
                if operand.mem.base == X86_REG_RIP:
                    value = insn.address + insn.size + operand.mem.disp
                    is_pcrel = True
                else:
                    value = operand.mem.disp
                    if '@GOTOFF' in op_str:
                        value += self.got_addr
                    is_pcrel = False

                res = FactorList(parser.parse(op_str), value, self.label_to_addr)
                if res.has_label():
                    components.append(Component(res.get_terms(), value, is_pcrel))
                else:
                    components.append(Component())
            else:
                pass

        if self.cs.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            components.reverse()
        return components



    def normalize_inst(self):
        text_start = self.prog.text_base
        text_end = self.prog.text_base + len(self.prog.text_data)

        for i, (addr, tokens, line) in enumerate(self.addressed_asms):
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
                #if addr in [0x402481]:
                #    import pdb
                #    pdb.set_trace()
                inst = self.prog.disasm(self.cs, addr, next_addr - addr)

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
            terms = self.parse_data_expr(token.strip())
            component = Component(terms)
            self.prog.Data[addr] = Data(addr, component, self.reassem_path, line)
            #print('Data:', hex(addr))

    def parse_data_expr(self, op_str):

        if self.cs.syntax == capstone.CS_OPT_SYNTAX_ATT:
            parser = ATTExParser()
        elif self.cs.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            parser = IntelExParser()

        value = 0
        result = FactorList(parser.parse(op_str), value, self.label_to_addr)

        return result.get_terms()



    @abstractmethod
    def address_src_file(self):
        pass


'''
class NormalizeATTSyntax(NormalizeTool):
    def parse_data_expr(self, s, v):
        token = ''
        tokens = []
        # Parsing
        for c in s:
            if is_operator(c):
                if len(token) > 0:
                    tokens.append(token)
                tokens.append(c)
                token = ''
            elif c in '()':
                if len(token) > 0 and not token.split()[0].startswith('%'):
                    tokens.append(token)
                token = ''
            else:
                token += c

        tokens.append(token)

        tokens, const = reduce_const_term(tokens, self.relocs)
        terms = []

        for token in tokens:
            if not is_operator(token):
                lbl = self.parse_label(token, v)
                terms.append(lbl)

        if const != 0:
            terms.append(const)

        return terms

    def get_label_expr(self, s):
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



class NormalizeIntelSyntax(NormalizeTool):

    def get_label_expr(self, s):
        if re.search('.* PTR \[.*\]', s):
            expr = re.findall('.* PTR \[(.*)\]', s)[0]

        elif re.search('OFFSET .*', s):
            expr = re.findall('OFFSET (.*)', s)[0]
        elif re.search ('.* PTR fs:.*', s):
            return ''
        elif len(s.split()) == 1:
            expr = s
        else:
            assert 0

        #return refine(expr)
        return expr


def has_non_digits(s):
    digits = "0123456789+-"
    for c in s:
        if c not in digits:
            return True
    return False

def is_gotoff(s):
    return '@GOTOFF' in s

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

def get_data_size(line):
    directive = line.split()[0]
    if directive.startswith('.byte'):
        return 1
    elif directive.startswith('.short'):
        return 2
    elif directive.startswith('.long'):
        return 4
    elif directive.startswith('.quad'):
        return 8
    elif directive.startswith('.zero'):
        n = int(line.split()[1])
        return n
    elif directive.startswith('.string') or directive.startswith('.asciz'):
        token = '"'.join(line.split('"')[1:])[:-1]
        return len(token) + 1
    elif directive.startswith('.ascii'):
        token = '"'.join(line.split('"')[1:])[:-1]
        return len(token)

    print(line)
    sys.exit(-1)
'''
