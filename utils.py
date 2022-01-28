PACKAGES = [
    "spec_cpu2006",
    "binutils-2.31.1",
    "coreutils-8.30"
]

ARCHS = ["x64", "x86"]
COMPILERS = ["clang", "gcc"]
PIES = ["pie", "nopie"]
OPTS = [
    "o0-bfd", "o1-bfd", "o2-bfd", "o3-bfd", "os-bfd", "ofast-bfd",
    "o0-gold", "o1-gold", "o2-gold", "o3-gold", "os-gold", "ofast-gold"
]
#ARCHS = ["x64"]
#COMPILERS = ["gcc"]
#PIES = ["nopie"]
#OPTS=["ofast-gold"]

def gen_options():
    for package in PACKAGES:
        for arch in ARCHS:
            for compiler in COMPILERS:
                for pie in PIES:
                    for opt in OPTS:
                        yield (package, arch, compiler, pie, opt)

# ----

import re

RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_\\.]+[:]')
RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9]')

# ----

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import struct

def load_elf(bin_path):
    return ELFFile(open(bin_path, 'rb'))

def get_arch(elf):
    return elf.get_machine_arch()

def get_text(elf):
    text = elf.get_section_by_name('.text')
    addr = text['sh_addr']
    data = text.data()
    return addr, data

def get_section(elf, addr):
    for section in elf.iter_sections():
        sec_addr = section['sh_addr']
        sec_size = section['sh_size']
        if sec_addr <= addr and addr < sec_addr + sec_size:
            return section
    return None

def get_bytes(elf, addr, sz):
    section = get_section(elf, addr)
    if not section:
        return 0
    base = section['sh_addr']
    offset = addr - base
    data = section.data()
    data = data[offset:offset + sz]
    return data

def get_int(elf, addr, sz = 4):
    section = get_section(elf, addr)
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

def get_got(elf):
    got = elf.get_section_by_name('.got.plt')
    addr = got['sh_addr']
    return addr

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

# ----

import capstone

def get_disassembler(arch):
    if arch == "x64":
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    return cs
