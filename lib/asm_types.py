from enum import Enum
from lib.utils import *
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

class Component:
    def __init__(self, terms=[], value=0, is_pcrel=False):
        self.Terms = terms
        self.Value = value
        if is_pcrel:
            self.Ty = CmptTy.PCREL
        else:
            numlbl = 0
            has_got = False
            for lbl in self.Terms:
                if isinstance(lbl, Label):
                    numlbl += 1
                    if lbl.Ty == LblTy.GOTOFF:
                        has_got = True
            if has_got:
                self.Ty = CmptTy.GOTOFF
            elif numlbl >= 2: # XXX: check '-'?
                self.Ty = CmptTy.OBJREL
            elif numlbl == 1:
                self.Ty = CmptTy.ABSOLUTE
            else:
                self.Ty = CmptTy.NONE

    def is_ms(self):
        return len(self.Terms) > 0

    def is_composite(self):
        return len(self.Terms) > 1

    def get_labels(self):
        if len(self.Terms) == 0:
            return []
        elif isinstance(self.Terms[-1], Label):
            return self.Terms
        else:
            return self.Terms[:-1]

    def __eq__(self, other):
        if len(self.Terms) == len(other.Terms):
            for i in range(len(self.Terms)):
                if self.Terms[i] != other.Terms[i]:
                    return False
            return True
        else:
            return False

    def to_json(self):
        terms = []
        for t in self.Terms:
            terms.append('%s' % t)
        value = self.Value
        ty = cmptTyToStr(self.Ty)
        j = {
                'Terms': terms,
                'Value': value,
                'Type': ty
                }
        return j

class Table:
    def __init__(self, name, addr, entries, entrySize):
        self.Name = name
        self.Address = addr
        self.Entries = entries
        self.EntrySize = entrySize

class Instr:
    def __init__(self, addr, components, path, line):
        self.Address = addr
        self.Components = components
        self.Path = path
        self.Line = line

    def get_components(self):
        res = []
        for idx, component in enumerate(self.Components):
            if component.is_ms():
                res.append(idx)
        return res

    # FIXME
    def get_operand_type(self, idx):
        return self.Operands[idx].get_type()

    # FIXME
    def get_operand_label(self, idx):
        assert self.Operands[idx].get_label()

    # FIXME
    def get_operand_value(self, idx):
        return self.Operands[idx].get_label().get_value()

    def get_type_str(self, opty):
        if opty == LblTy.GOTOFF:
            return "GOTOFF"
        else:
            return "LABEL"

    def print_operands(self):
        s = ''
        for operand in self.Operands:
            ty = operand.get_type()
            s += "%s " % self.get_type_str(ty)
        return s

    def __str__(self):
        s = ''
        s += "%x " % self.Address
        s += self.print_operands()
        return s

class Data:
    def __init__(self, addr, component, path, line):
        self.Address = addr
        self.Component = component
        self.Path = path
        self.Line = line

class Program:
    def __init__(self, elf, cs):
        self.Instrs = {}
        self.Data = {}
        self.Tables = {}

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
