from abc import abstractmethod
from collections import namedtuple
import re
from lib.types import Label, LblTy, DataType, InstType
import capstone
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

REGISTERS = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP','R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D',
        'AX', 'BX', 'CX', 'DX', 'BP', 'SI', 'DI', 'SP', 'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W',
        'AH', 'BH', 'CH', 'DH',
        'AL', 'BL', 'CL', 'DL', 'BPL', 'SIL', 'DIL', 'SPL', 'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B',
        'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8', 'XMM9', 'XMM10',
        'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15',
        'RIP'
]

DATA_DIRECTIVE = ['.byte', '.asciz', '.quad', '.ascii', '.long', '.short', '.string', '.zero']
SKIP_DIRECTIVE = ['.align', '.globl', '.type']
jump_instrs =  ["jo","jno","js","jns","je", "jz","jne", "jnz","jb", "jna", "jc","jnb", "jae", "jnc","jbe", "jna","ja", "jnb","jl", "jng","jge", "jnl","jle", "jng","jg", "jnl","jp", "jpe","jnp", "jpo","jcx", "jec", 'jmp', 'jmpl', 'jmpq']

ReasmInst = namedtuple('ReasmInst', ['asm_line', 'opcode', 'operand_list', 'addr', 'idx'])
ReasmData = namedtuple('ReasmData', ['asm_line', 'directive', 'expr', 'addr', 'idx'])
ReasmLabel = namedtuple('ReasmLabel', ['label', 'addr', 'idx'])

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
    def __init__(self, label_to_addr = None, syntax = capstone.CS_OPT_SYNTAX_ATT, got_addr = 0):
        self.label_to_addr = label_to_addr

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
            factors = FactorList(tokens, value, self.label_to_addr)
        return DataType(addr, asm_path, line, idx, factors, r_type = r_type)
        #return Component(factors)

    def rearrange_operands(self, addr, asm_path, asm_token, insn):
        '''
        # sarl $1, %eax     vs. salr %eax
        # salw $1, -6(%rbp) vs. salw -6(%rbp)
        # sarw $1, %ax          vs. sarw %ax
        # shrq $1, %rax     vs. shrq %rax
        # shll $1, -0x3b4(%rbp) vs sall -948(%rbp)
        # shrl $1, -0x3b0(%rbp) vs shrl -944(%rbp)
        # shrw $1, -0x106(%rbp) vs shrw -262(%rbp)
        # sarq $1, %rdx     vs  sarq %rdx
        # sarl $1, %eax     vs  sarl %eax
        # shrw $1, -0x106(%rbp) vs. shrw -262(%rbp)
        # shrb $1, %al          vs. shrb %al
        if re.match('s[ah][rl].', asm_token.opcode):
            pass
        # rol $1, %eax          vs. roll %r9d
        elif re.match('ro[rl].', asm_token.opcode):
            pass
        # repne scasb (%rdi), %al vs. repnz scasb
        # rep movsq (%rsi), (%rdi) vs. rep movsq
        # repe cmpsb (%rdi), (%rsi) vs. repz cmpsb
        elif asm_token.opcode.startswith('rep'):
            pass
        #movsb (%rsi), (%rdi)  vs. movsb
        elif re.search('movs. \(%.si\), \(%.di\)', str(insn)):
            pass
        else:
            print(insn)
            print('%s (%s)'%(asm_token.opcode, ' '.join(asm_token.operand_list)))
            print('%d %d'%(len(insn.operands), len(asm_token.operand_list)))
            return [Component()]


        '''
        #op_str_list = []
        if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
            op_str = asm_token.operand_list[0]
            tokens = self.ex_parser.parse(op_str)
            value = insn.operands[0].imm + insn.address + insn.size
            factors = FactorList(tokens, value, is_pcrel=True)
            if factors.has_label():
                return InstType(addr, asm_path, asm_token, imm = factors)
            return InstType(addr, asm_path, asm_token)

        # get the value of relocatable expression
        disp_list = []
        imm_list = []
        for operand in insn.operands:
            if operand.type == X86_OP_MEM:
                disp_list.append(operand.mem.disp)
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
                    imm = self.create_component(op_str, imm_list[0], insn)
                else:
                    if len(disp_list) == 0 and len(imm_list) == 1:
                        # assembler might change RIP-relativea addressing to absolute addressing
                        # movq ext_ncd_write_field_@GOTPCREL(%rip), %rdi
                        #  ->  mov    $0x8c4340,%rdi
                        if '(%rip)' in op_str:
                            assert len(imm_list) == 1 and imm is None, 'Unexpected operand type'
                            imm = self.create_component(op_str.split('(%rip)')[0], imm_list[0], insn)
                            continue
                        elif '@GOT(' in op_str:
                            assert len(imm_list) == 1 and imm is None, 'Unexpected operand type'
                            imm = self.create_component(op_str.split('(')[0], imm_list[0], insn)
                            continue

                    #if len(disp_list) != 1 or disp is not None:
                    #    import pdb
                    #    pdb.set_trace()
                    assert len(disp_list) == 1 and disp is None, 'Unexpected operand type'
                    disp = self.create_component(op_str, disp_list[0], insn)

        return InstType(addr, asm_path, asm_token, disp=disp, imm=imm)
        '''
        components = []
        for idx, op_str in enumerate(op_str_list):
            value = value_list[idx]

            if '@GOTOFF' in op_str:
                value += self.got_addr
            if '_GLOBAL_OFFSET_TABLE_' in op_str:
                gotoff = self.got_addr - insn.address
            else:
                gotoff = 0

            tokens = self.ex_parser.parse(op_str)
            is_pcrel = self.ex_parser.has_rip

            factors = FactorList(tokens, value, self.label_to_addr, gotoff)

            if factors.has_label():
                components.append(Component(factors, is_pcrel))
            else:
                components.append(Component())

        if self.syntax == capstone.CS_OPT_SYNTAX_INTEL:
            components.reverse()

        return components
        '''

    def create_component(self, op_str, value = 0, insn = None):


        tokens = self.ex_parser.parse(op_str)
        is_pcrel = self.ex_parser.has_rip

        if value:
            if '@GOTOFF' in op_str:
                value = (value + self.got_addr) & 0xffffffff
            elif '_GLOBAL_OFFSET_TABLE_' in op_str:
                #gotoff = self.got_addr - insn.address
                value = self.got_addr
                pass
            else:
                if is_pcrel:
                    value += insn.address + insn.size

            factors = FactorList(tokens, value, is_pcrel = is_pcrel)
        else:
            factors = FactorList(tokens, label_to_addr = self.label_to_addr, is_pcrel = is_pcrel)

        if factors.has_label():
            if len(factors.terms) == 3 and factors.terms[0].get_name() == '_GLOBAL_OFFSET_TABLE_':
                factors.terms[0].Address = self.got_addr
                factors.terms[1].Address = insn.address
                factors.terms[2].Address = self.got_addr - value
            return factors

        return None


    def get_instr(self, addr, asm_path, asm_token, insn=None):

        if asm_token.opcode.startswith('nop'):
            return InstType(addr, asm_path, asm_token)

        if insn:
            return self.rearrange_operands(addr, asm_path, asm_token, insn)


        if asm_token.opcode.startswith('call') or asm_token.opcode in jump_instrs:
            op_str = asm_token.operand_list[0]
            tokens = self.ex_parser.parse(op_str)
            factors = FactorList(tokens, label_to_addr = self.label_to_addr, is_pcrel=True)
            if factors.has_label():
                return InstType(addr, asm_path, asm_token, imm = factors)
            return InstType(addr, asm_path, asm_token)

        imm = None
        disp = None
        for op_str in asm_token.operand_list:
            tokens = self.ex_parser.parse(op_str)
            is_pcrel = self.ex_parser.has_rip
            factors = FactorList(tokens, label_to_addr = self.label_to_addr, is_pcrel = is_pcrel)
            if factors.has_label():
                if self.ex_parser.is_imm:
                    imm = self.create_component(op_str)
                else:
                    disp = self.create_component(op_str)

        return InstType(addr, asm_path, asm_token, disp=disp, imm=imm)


class FactorList:
    def __init__(self, factors, value=0, label_to_addr=None, is_pcrel=False):
        self.labels = []
        self.num = 0
        self.value = value
        self._label_to_addr = label_to_addr
        #self.gotoff = gotoff
        self.is_pcrel = is_pcrel
        for factor in factors:
            if factor.data.isdigit() or factor.data.startswith('0x'):
                self.num += eval(factor.get_str())
            else:
                self.labels.append(factor.get_str())
        # exclude ddisasm bugs
        if len(self.labels) == 2 and self.labels[-1] not in ['-_GLOBAL_OFFSET_TABLE_']:
            self.terms = self.get_table_terms()
        elif self.has_label():
            self.terms = self.get_terms()
        else:
            self.terms = []
        self._label_to_addr = None
        self.type = self.get_type()

    def get_type(self):
        if len(self.labels) == 2:
            return 7
        elif len(self.labels) == 1:
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
        return self.has_label() and (len(self.terms) > 1 or self.num != 0)

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
                #addr = self.gotoff
                addr = 0
                label_type = LblTy.LABEL
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
                if len(self.labels) == 3 and '_GLOBAL_OFFSET_TABLE_' in self.labels[0]:
                    pass
                # handle ddisasm bugs
                elif len(self.labels) == 2 and self.labels[-1] == '-_GLOBAL_OFFSET_TABLE_':
                    pass
                elif len(self.labels) > 1:
                    import pdb
                    pdb.set_trace()
                    raise SyntaxError('Unsolved label')
                addr = self.value - self.num

            lbl = Label(label, label_type, addr)
            result.append(lbl)
        if self.num:
            return result + [self.num]
        return result

    def get_table_terms(self):
        base_label = self.labels[1][1:]
        base_addr = self.label_to_addr(base_label)
        if base_addr <= 0:
            import pdb
            pdb.set_trace()
        assert base_addr > 0, 'This is incorrect jump table base'

        if self.value == 0:
            addr1 = self.label_to_addr(self.labels[0])
        else:
            addr1 = (self.value + base_addr ) & 0xffffffff

        lbl1 = Label(self.labels[0], LblTy.LABEL, addr1)
        lbl2 = Label(self.labels[1], LblTy.LABEL, base_addr)

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
            import pdb
            pdb.set_trace()
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
                expr = re.findall('^\((.*)\)\(.*\)$', expr)
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
        elif self._is_next(r'[_.a-zA-Z0-9@]*'):
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
            self.is_imm = True

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
            #import pdb
            #pdb.set_trace()
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


