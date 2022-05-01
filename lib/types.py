from enum import Enum
from elftools.elf.relocation import RelocationSection
import json

class LblTy(Enum):
    GOTOFF = 1
    LABEL = 2

class CmptTy(Enum):
    ABSOLUTE = 1
    PCREL = 2
    GOTOFF = 3
    OBJREL = 4
    NONE = 5

class ReportTy(Enum):
    UNKNOWN = 0
    TP = 1
    FP = 2
    FN = 3
    TF = 4

def cmptTyToStr(ty):
    if ty == CmptTy.ABSOLUTE:
        return 'ABSOLUTE'
    elif ty == CmptTy.PCREL:
        return 'PCREL'
    elif ty == CmptTy.GOTOFF:
        return 'GOTOFF'
    elif ty == CmptTy.OBJREL:
        return 'OBJREL'
    else:
        return 'NONE'

class Label:
    def __init__(self, name, ty, addr):
        self.Address = addr
        self.Name = name
        self.Ty = ty

    def get_value(self):
        return self.Address

    def get_name(self):
        return self.Name

    def get_type(self):
        return self.Ty

    def __eq__(self, other):
        if not isinstance(other, Label):
            return False
        #return self.Address == other.Address and self.Ty == other.Ty
        #HSKIM. allow external symbol
        return (self.Address == other.Address or other.Address == -1) and self.Ty == other.Ty

    def __str__(self):
        if self.Address is None:
            addr = 0
        else:
            addr = self.Address
        if self.Ty == LblTy.GOTOFF:
            s = 'GOTOFF'
        else:
            s = 'LABEL'
        return 'Label ' + hex(addr) + ' ' + s

class InstType:
    def __init__(self, addr, path, asm_token=None, imm=None, disp=None):
        self.addr = addr
        self.path = path
        self.asm_token = asm_token
        if asm_token:
            self.asm_line = asm_token.asm_line
            self.asm_idx = asm_token.idx
        else:
            self.asm_line = ''
            self.asm_idx = 0
        self.imm = imm
        self.disp = disp

class DataType:
    def __init__(self, addr, path, asm_line, idx, value=None, r_type=None):
        self.addr = addr
        self.path = path
        self.asm_line = asm_line
        self.asm_idx = idx
        self.value = value
        self.r_type = r_type


def get_text(elf):
    text = elf.get_section_by_name('.text')
    addr = text['sh_addr']
    data = text.data()
    return addr, data

def get_reloc_addrs(elf):
    reloc_addrs = []
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symbol_table = elf.get_section(section['sh_link'])
        for relocation in section.iter_relocations():
            symbol = symbol_table.get_symbol(relocation['r_info_sym'])
            addr = relocation['r_offset']
            if symbol.name:
                reloc_addrs.append(addr)
    return reloc_addrs

class Program:
    def __init__(self, elf, cs):
        self.Instrs = {}
        self.Data = {}
        #self.Tables = {}

        text_base, text_data = get_text(elf)

        self.text_base = text_base
        self.text_data = text_data
        self.relocs = set(get_reloc_addrs(elf))

        self.sections = []
        for section in elf.iter_sections():
            sec_addr = section['sh_addr']
            sec_size = section['sh_size']
            sec_name = section.name
            self.sections.append((sec_addr, sec_size, sec_name))

        self.unknown_region = set()
        self.aligned_region = set()

    def get_section(self, addr):
        for section in self.sections:
            sec_addr, sec_size, sec_name = section
            if sec_addr <= addr and addr < sec_addr + sec_size:
                return sec_name
        return ''

    def is_linker_generated_section(self, name):
        # FIXME
        return name == '.got'

    def is_valid_addr(self, addr):
        for section in self.sections:
            sec_addr, sec_size, sec_name = section
            if sec_addr <= addr and addr < sec_addr + sec_size:
                return True
        return False

    def is_reloc_defined(self, addr):
        return addr in self.relocs

    def get_got_addr(self, elf):
        return get_got(elf)

    def disasm(self, cs, addr, length):
        offset = addr - self.text_base
        data = self.text_data[offset:offset+length]
        inst = list(cs.disasm(data, addr))[0]
        return inst

    def disasm_range(self, cs, addr, length):
        offset = addr - self.text_base
        if length == -1:
            data = self.text_data[offset:]
        else:
            data = self.text_data[offset:offset+length]
        insts = list(cs.disasm(data, addr))
        return insts
