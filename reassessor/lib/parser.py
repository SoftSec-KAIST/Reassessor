from abc import abstractmethod
from collections import namedtuple
import re
from .types import Label, LblTy, DataType, InstType
import capstone
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

REGISTERS = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP','R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D',
        'AX', 'BX', 'CX', 'DX', 'BP', 'SI', 'DI', 'SP', 'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W',
        'AH', 'BH', 'CH', 'DH',
        'AL', 'BL', 'CL', 'DL', 'BPL', 'SIL', 'DIL', 'SPL', 'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B',
        'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8', 'XMM9', 'XMM10',
        'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15',
        'RIP',
        'CS', 'DS', 'ES', 'FS', 'GS', 'SS',
        'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7'
]

DATA_DIRECTIVE = ['.byte', '.asciz', '.quad', '.ascii', '.long', '.short', '.string', '.zero']
SKIP_DIRECTIVE = ['.align', '.globl', '.type']
jump_instrs =  ["jo","jno","js","jns","je", "jz","jne", "jnz","jb", "jna", "jc","jnb", "jae", "jnc","jbe", "jna","ja", "jnb","jl", "jng","jge", "jnl","jle", "jng","jg", "jnl","jp", "jpe","jnp", "jpo","jcx", "jec", 'jmp', 'jmpl', 'jmpq']

ReasmInst = namedtuple('ReasmInst', ['asm_line', 'opcode', 'operand_list', 'addr', 'idx'])
ReasmData = namedtuple('ReasmData', ['asm_line', 'directive', 'expr', 'addr', 'idx'])
ReasmLabel = namedtuple('ReasmLabel', ['label', 'addr', 'idx'])
ReasmSetLabel = namedtuple('ReasmSetLabel', ['label', 'addr', 'num', 'idx'])


def parse_set_directive(line, label_to_addr):

    label = line.split(',')[0].split()[1]
    exprs = line.split(',')[1].split()

    new_exprs = []
    new_labels = []
    for expr in exprs:
        if expr.isdigit() or expr in ['+', '-', '*'] or expr.startswith('0x'):
            new_exprs.append(expr)
        elif expr[0] in ['.'] or expr[0].isalpha():
            new_exprs.append('0')
            new_labels.append(expr)
        else:
            assert False, 'Unknown expression'

    num = eval(''.join(new_exprs))

    assert len(new_labels) < 2, 'Invalid expression'

    xaddr = -1
    if new_labels:
        if '.' == new_labels[0]:
            # .set FUN_804a3f0, . - 10
            # FUN_804a3f0 = . - 10
            # . = FUN_804a3f0 - (- 10)
            xaddr = label_to_addr(label) - num
        else:
            xaddr = label_to_addr(new_labels[0])

    return xaddr, num



class AsmTokenizer:
    def __init__(self, syntax):
        self.syntax = syntax

    def parse(self, asm_line, addr=0, idx=0):
        terms = asm_line.split()
        opcode = terms[0]
        if opcode.startswith('nop'):
            op_str = ''
        elif opcode.startswith('rep'):
            opcode = ' '.join(terms[:2])
            op_str = ' '.join(terms[2:])
        elif opcode in ['lock', 'bnd']:
            #ddisasm disassembl error
            opcode = ' '.join(terms[:2])
            op_str = ' '.join(terms[2:])
        else:
            op_str = ' '.join(terms[1:])

        if self.syntax == capstone.CS_OPT_SYNTAX_ATT:
            operand_list = self._parse_att_operands(op_str)
        else:
            operand_list = self._parse_intel_operands(op_str)

        return ReasmInst(asm_line, opcode, operand_list, addr, idx)

    def parse_data(self, asm_line, addr=0, idx=0):
        terms = asm_line.split()
        directive = terms[0]
        expr = terms[1]
        return ReasmData(asm_line, directive, expr, addr, idx)

    def _parse_intel_operands(self, op_str):
        if op_str.strip():
            return op_str.split(',')
        return []

    def _parse_att_operands(self, op_str):
        token = ''
        lpar = False
        operand_list = []
        for char in op_str:
            if lpar:
                token += char
                if char == ')':
                    lpar = False
                continue
            if char == ',':
                operand_list.append(token)
                token = ''
                continue
            if char == ' ':
                continue

            token += char
            if char == '(':
                lpar = True
        if token:
            operand_list.append(token)

        return operand_list



def parse_intel_asm_line(line):
    prev = line.split(',')[0]
    args = line.split(',')[1:]

    if line in ['nop']:
        opcode = 'nop'
        arg1 = ''
        return ['nop', []]
    elif prev.split()[0] in ['rep', 'repe', 'repz', 'repne', 'repnz']:
        opcode = ' '.join(prev.split()[:2])
        arg1 = ' '.join(prev.split()[2:])
    elif prev.split()[0] in ['lock']:
        #ddisasm disassembl error
        opcode = ' '.join(prev.split()[:2])
        arg1 = ' '.join(prev.split()[2:])
    else:
        opcode = prev.split()[0]
        arg1 = ' '.join(prev.split()[1:])

    ret = [opcode,[]]
    if arg1:
        ret[1].append(arg1)
        for arg in args:
            ret[1].append(arg)
    return ret


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

class CompGen:
    def __init__(self, label_dict = None, syntax = capstone.CS_OPT_SYNTAX_ATT, got_addr = 0, label_func=None, set_label_dict = None):
        self.label_dict = dict()
        if label_dict:
            self.label_dict = label_dict

        self.set_label_dict = dict()
        if set_label_dict:
            self.set_label_dict = set_label_dict

        self.label_func = label_func

        self.syntax = syntax
        if syntax == capstone.CS_OPT_SYNTAX_INTEL:
            self.ex_parser = IntelExParser()
        else:
            self.ex_parser = ATTExParser()

        self.got_addr = got_addr

    def get_data(self, addr, asm_path, line, idx , value=0, additional_dict=None, r_type=None):
        expr = ''.join(line.split()[1:])
        tokens = self.ex_parser.parse(expr)

        if len(tokens) == 1 and expr.endswith('@GOTOFF'):
            value = (value + self.got_addr) & 0xffffffff

        if additional_dict:
            factors = FactorList(tokens, value, additional_dict)
        else:
            factors = FactorList(tokens, value, self.label_dict, self.label_func, set_label_dict = self.set_label_dict)
        return DataType(addr, asm_path, line, idx, factors, r_type = r_type)
        #return Component(factors)

    def rearrange_operands(self, addr, asm_path, asm_token, insn):
        #op_str_list = []
        if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
            op_str = asm_token.operand_list[0]
            tokens = self.ex_parser.parse(op_str)
            if insn.operands[0].type == X86_OP_MEM:
                if insn.operands[0].mem.base == X86_REG_RIP:
                    value = insn.operands[0].mem.disp + insn.address + insn.size
                elif '@GOTOFF' in op_str:
                    value = insn.operands[0].mem.disp
                    value = (value + self.got_addr) & 0xffffffff
                else:
                    value = insn.operands[0].mem.disp
            else:
                value = insn.operands[0].imm
            factors = FactorList(tokens, value, is_pcrel=True, set_label_dict = self.set_label_dict)
            if factors.has_label():
                return InstType(addr, asm_path, asm_token, imm = factors)
            return InstType(addr, asm_path, asm_token)

        # get the value of relocatable expression
        disp_list = []
        imm_list = []
        for operand in insn.operands:
            if operand.type == X86_OP_MEM:
                if operand.mem.base == X86_REG_RIP:
                    value = operand.mem.disp + insn.address + insn.size
                else:
                    value = operand.mem.disp
                disp_list.append(value)
            elif operand.type == X86_OP_IMM:
                imm_list.append(operand.imm)

        if len(disp_list)+len(imm_list) == 0: # or asm_token.opcode.startswith('rep'):
            return InstType(addr, asm_path, asm_token)


        #match reloc expressions to values
        disp = None
        imm = None
        for op_str in asm_token.operand_list:
            tokens = self.ex_parser.parse(op_str)
            factors = FactorList(tokens)
            if factors.has_label():
                if self.ex_parser.is_imm:
                    assert len(imm_list) == 1 and imm is None, 'Unexpected operand type'
                    imm = self.create_component(addr, op_str, imm_list[0])
                else:
                    if len(disp_list) == 0 and len(imm_list) == 1:
                        # assembler might change RIP-relativea addressing to absolute addressing
                        # movq ext_ncd_write_field_@GOTPCREL(%rip), %rdi
                        #  ->  mov    $0x8c4340,%rdi
                        if '(%rip)' in op_str:
                            assert len(imm_list) == 1 and imm is None, 'Unexpected operand type'
                            imm = self.create_component(addr, op_str.split('(%rip)')[0], imm_list[0])
                            continue
                        elif '@GOT(' in op_str:
                            assert len(imm_list) == 1 and imm is None, 'Unexpected operand type'
                            imm = self.create_component(addr, op_str.split('(')[0], imm_list[0])
                            continue

                    assert len(disp_list) == 1 and disp is None, 'Unexpected operand type'


                    disp = self.create_component(addr, op_str, disp_list[0])

        return InstType(addr, asm_path, asm_token, disp=disp, imm=imm)

    def create_component(self, addr, op_str, value = 0):

        tokens = self.ex_parser.parse(op_str)
        is_pcrel = self.ex_parser.has_rip

        if value:   #in case of GT
            if '@GOTOFF' in op_str:
                value = (value + self.got_addr) & 0xffffffff
            elif '@GOT' in op_str and '@GOTPCREL' not in op_str:
                value = (value + self.got_addr) & 0xffffffff
            elif '_GLOBAL_OFFSET_TABLE_' in op_str:
                value = self.got_addr

            factors = FactorList(tokens, value, is_pcrel = is_pcrel)
        else:       #in case of TOOLs
            factors = FactorList(tokens, label_dict = self.label_dict, is_pcrel = is_pcrel, label_func = self.label_func, set_label_dict= self.set_label_dict)

        if factors.has_label():
            if len(factors.terms) == 3 and factors.terms[0].get_name() == '_GLOBAL_OFFSET_TABLE_':
                factors.terms[0].Address = self.got_addr
                factors.terms[1].Address = addr
                factors.terms[2].Address = self.got_addr - value
            return factors

        return None


    def get_instr(self, addr, asm_path, asm_token, insn=None):

        if asm_token.opcode.startswith('nop'):
            return InstType(addr, asm_path, asm_token)

        # GT uses capstone IR
        if insn:
            return self.rearrange_operands(addr, asm_path, asm_token, insn)


        if asm_token.opcode.startswith('call') or asm_token.opcode in jump_instrs:
            op_str = asm_token.operand_list[0]
            tokens = self.ex_parser.parse(op_str)
            factors = FactorList(tokens, label_dict = self.label_dict, is_pcrel=True, label_func = self.label_func, set_label_dict= self.set_label_dict)
            if factors.has_label():
                return InstType(addr, asm_path, asm_token, imm = factors)
            return InstType(addr, asm_path, asm_token)

        imm = None
        disp = None
        for op_str in asm_token.operand_list:
            tokens = self.ex_parser.parse(op_str)
            is_pcrel = self.ex_parser.has_rip
            factors = FactorList(tokens, label_dict = self.label_dict, is_pcrel = is_pcrel, label_func = self.label_func, set_label_dict = self.set_label_dict)
            if factors.has_label():
                if self.ex_parser.is_imm:
                    imm = self.create_component(addr, op_str)
                else:
                    disp = self.create_component(addr, op_str)

        return InstType(addr, asm_path, asm_token, disp=disp, imm=imm)


class FactorList:
    def __init__(self, factors, value=0, label_dict=None, label_func=None, is_pcrel=False, set_label_dict=None):
        self.labels = []
        self.num = 0
        self.value = value
        self._label_dict = label_dict
        self._set_label_dict = set_label_dict
        self._label_func = label_func
        #self.gotoff = gotoff
        self.is_pcrel = is_pcrel
        for factor in factors:
            if factor.data.isdigit() or factor.data.startswith('0x'):
                self.num += eval(factor.get_str())
            else:
                self.labels.append(factor.get_str())



        if len(self.labels) == 2:
            # exclude ddisasm bugs
            if self.labels[-1] in ['-_GLOBAL_OFFSET_TABLE_']:#, '-.L_0']:
                self.terms = self.get_ddisasm_got_terms()
            else:
                self.terms = self.get_table_terms()
        elif self.has_label():
            self.terms = self.get_terms()
        else:
            self.terms = []
        self._label_dict = None
        self._set_label_dict = None
        self._label_func = None
        self.type = self.get_type()

    def get_type(self):

        if len(self.labels) == 2:
            #ddisasm makes type 5/6 symbol like XXX-_GLOBAL_OFFSET_TABLE_
            if self.labels[1] == '-_GLOBAL_OFFSET_TABLE_':

                #if self.terms[0].Address == -1:
                #    return 0
                if self.is_composite():
                    return 6
                else:
                    return 5
            # .quad FUN_40b230-.L_0
            elif self.terms[1].Address == -1 and self.terms[1].Num == 0:
                return 1
            else:
                return 7
        elif len(self.labels) == 1:

            #if self.terms[0].Address == -1:
            #    return 0

            if ('@GOTOFF' in self.labels[0] or '@GOT' in self.labels[0]) and '@GOTPCREL' not in self.labels[0]:
                if self.is_composite():
                    return 6
                else:
                    return 5
            elif self.is_pcrel:
                if self.is_composite():
                    return 4
                else:
                    return 3
            else:
                if self.is_composite():
                    return 2
                else:
                    return 1
        elif len(self.labels) == 3 and '_GLOBAL_OFFSET_TABLE_' in self.labels[0]:
            return 7
        return 8

    def has_label(self):
        return len(self.labels) > 0

    def is_composite(self):
        return self.has_label() and (len(self.terms) > 1 or self.num != 0 or (self.terms[0].Num != 0 and self.terms[0].Address != -1))

    def get_norm_str(self):
        ret = ''
        for term in self.terms:
            if isinstance(term, Label):
                if ret:
                    if term.get_name()[0] == '-':
                        ret += '-' + str(term)
                    else:
                        ret += '+' + str(term)
                else:
                    ret = str(term)
            elif term < 0:
                ret += '-%s'%(hex(-term))
            else:
                ret += '+%s'%(hex(term))
        return ret


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
        if self._label_dict is None:
            return 0

        keyword = label.split('@')[0]
        if keyword in self._label_dict:
            res = self._label_dict[keyword]
            if isinstance(res, list):
                if len(self._label_dict[keyword]) == 1:
                    return self._label_dict[keyword][0]
                else:
                    #if there is duplicated label, we nullify the label
                    return -2
            return self._label_dict[keyword]
        elif self._label_func:
            addr = self._label_func(keyword)
            if addr > 0:
                return addr

        return -1

    def is_set_label(self, keyword):
        if not self._set_label_dict:
            return False
        if keyword in self._set_label_dict:
            return True
        return False



    def get_ddisasm_got_terms(self):
        assert len(self.labels) == 2 and self.labels[1] == '-_GLOBAL_OFFSET_TABLE_'

        result = []

        addr = self.label_to_addr(self.labels[0])
        label_type = LblTy.GOTOFF
        lbl = Label(self.labels[0], label_type, addr, 0)
        result.append(lbl)

        if self.num:
            return result + [self.num]
        return result

    def get_terms(self):
        result = []

        for label in self.labels:
            keyword = ''
            implicit_num = 0

            if '_GLOBAL_OFFSET_TABLE_' in label:
                #addr = self.gotoff
                addr = 0
                label_type = LblTy.LABEL
            #elif '@GOTOFF' in label:
            elif '@GOT' in label:
                #keyword = label.split('@GOTOFF')[0]
                keyword = label.split('@GOT')[0]
                label_type = LblTy.GOTOFF
            else:
                if label[0] == '-':
                    keyword = label[1:]
                else:
                    keyword = label
                label_type = LblTy.LABEL

            if keyword:
                addr = self.label_to_addr(keyword)

                #check whether the label is defined by .set directive
                if addr in [0,-1] and self.is_set_label(keyword):
                    addr, implicit_num = self._set_label_dict[keyword][0]

            if addr <= 0 and self.value:
                if len(self.labels) == 3 and '_GLOBAL_OFFSET_TABLE_' in self.labels[0]:
                    pass
                # handle ddisasm bugs
                elif len(self.labels) == 2 and self.labels[-1] == '-_GLOBAL_OFFSET_TABLE_':
                    pass
                elif len(self.labels) > 1:
                    raise SyntaxError('Unsolved label')
                addr = self.value - self.num
            elif '@PLT' in label or '@GOTPCREL' in label:
                addr = 0


            lbl = Label(label, label_type, addr, implicit_num)
            result.append(lbl)
        if self.num:
            return result + [self.num]
        return result

    def get_table_terms(self):
        base_label = self.labels[1][1:]
        base_addr = self.label_to_addr(base_label)
        if self.value != 0 and base_addr <= 0:
            assert base_addr > 0, 'This is incorrect jump table base'

        if self.value == 0:
            addr1 = self.label_to_addr(self.labels[0])
        else:
            addr1 = (self.value + base_addr ) & 0xffffffff

        lbl1 = Label(self.labels[0], LblTy.LABEL, addr1, 0)
        lbl2 = Label(self.labels[1], LblTy.LABEL, base_addr, 0)

        return [lbl1, lbl2]


class ExParser:
    def __init__(self):
        self.line = ''
        self.current = ''

    def parse(self, expr):
        self.has_rip = False
        self.is_imm = False
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
        #remove offset & pointer directive
        if expr.startswith('$'):
            self.is_imm = True
            expr = expr[1:]
        elif expr.startswith('*'):
            expr = expr[1:]

        if re.search ('%fs:.*', expr):
            return ''
        elif re.search ('%es:.*', expr):
            return ''
        elif expr[0] == '%':
            return ''
        elif ':$' in expr:
            #handle ramblr diassem errors.
            # ljmpl $0x32dc:$0x3d80ffff
            return ''
        elif expr.startswith('_GLOBAL_OFFSET_TABLE_+'):
            # clang x86 pie
            # $_GLOBAL_OFFSET_TABLE_+(.Ltmp266-.L15$pb)
            expr = '%s+%s-%s'%(re.findall('^(.*)\+\((.*)-(.*)\)$', expr)[0])
        elif re.search('.*\(.*\)', expr):
            if '%rip' in re.findall('.*\((.*)\)', expr)[0]:
                self.has_rip = True

            # ramblr: movzbl  (label_4744+7)(%rdx),  %esi
            if re.search('^\(.*\)\(.*\)$', expr):
                expr = re.findall('^\((.*)\)\(.*\)$', expr)[0]
            # ramblr: movl $(label_4299+3), -316(%ebp)
            # ramblr: movw $0x808, (label_1293+2)
            elif ('%' not in expr) and re.search('^\(.*\)$', expr):
                expr = re.findall('\((.*)\)', expr)[0]
            else:
                expr = re.findall('(.*)\(.*\)', expr)[0]

            #if re.search('\(.*\)', expr):
            #    expr = re.findall('\((.*)\)', expr)[0]
        return expr

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
        #elif self._is_next(r'[_.a-zA-Z0-9@]*'):
        # for cgc clang 6.4
        elif self._is_next(r'[_.a-zA-Z0-9@$]*'):
            if self.line == '$pb':
                self.current += self.line
                self.line = ''
            return Factor('+', self.current)


        raise SyntaxError('Unexpect syntax' + self.line)


class IntelExParser(ExParser):
    def _strip(self, expr):
        if re.search('.* PTR \[.*\]', expr):
            expr = re.findall('.* PTR \[(.*)\]', expr)[0]
        elif re.search ('.* PTR .S:.*', expr):
            return ''
        elif re.match ('ST\(.*\)', expr):
            return ''
        elif re.search('^\[.*\]$', expr):
            expr = re.findall('^\[(.*)\]$', expr)[0]

        # add BYTE PTR [OFFSET _GLOBAL_OFFSET_TABLE_]
        if re.search('OFFSET .*', expr):
            expr = re.findall('OFFSET (.*)', expr)[0]
            if expr.startswith('_GLOBAL_OFFSET_TABLE_+'):
                # clang x86 pie
                # $_GLOBAL_OFFSET_TABLE_+(.Ltmp266-.L15$pb)
                expr = '%s+%s-%s'%(re.findall('^(.*)\+\((.*)-(.*)\)$', expr)[0])

            self.is_imm = True
        # give exception to handle ddisasm error
        elif re.search('\(.*-\.L\_0\)/2', expr) or re.search('\(.*-_GLOBAL_OFFSET_TABLE_\)/2',expr):
            expr = '%s-%s'%(re.findall('\((.*)-(.*)\)/2', expr)[0])

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

        if result and re.search('^[0-9]*@GOTOFF', result[-1].data):
            # [EBX+_ZN4Data5SetUpINS_12Exercise_2_3ILi3EEELi3EE15right_hand_sideE+12@GOTOFF]
            for factor in result[:-1]:
                if factor.data and not factor.data.isdigit():
                    factor.data += '@GOTOFF'
            result[-1].data = result[-1].data.split('@')[0]

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
            if self.current in ['RIP']:
                self.has_rip = True
            if self.current in REGISTERS: # ignore register
                return Factor(None, None)

            return Factor('+', self.current)

        elif self._is_next(r'-'):
            factor = self._factor()
            if factor.op == '+':
                return Factor('-', factor.data)

        raise SyntaxError('Unexpect syntax' + self.line)


