#!/usr/bin/python

import glob
import os
import asm_types
import sys
import pickle
import multiprocessing
from elftools.elf.elffile import ELFFile
from asm_types import CmptTy

total_cnt = 0

def get_functions(bin_path):
    elffile = ELFFile(open(bin_path, 'rb'))
    symtab = elffile.get_section_by_name('.symtab')
    dynsym = elffile.get_section_by_name('.dynsym')
    func_addrs = set()

    for symbol in symtab.iter_symbols():
        if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':
            addr = symbol['st_value']
            if addr != 0:
                func_addrs.add(addr)

    for symbol in dynsym.iter_symbols():
        if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':
            addr = symbol['st_value']
            if addr != 0:
                func_addrs.add(addr)
    
    return list(func_addrs)

def get_text(bin_path):
    elffile = ELFFile(open(bin_path, 'rb'))
    text = elffile.get_section_by_name('.text')
    addr = text['sh_addr']
    sz = len(text.data())
    return addr, sz


def run(line):
    global total_cnt

    pickle_dir = "../../tmp/pickles4/"
    path = line.strip()[17:]
    binname = os.path.basename(path)
    pickle_path = pickle_dir +  path[:-len(binname)]
    pickle_g_dir = pickle_path.replace("/bin/", "/")
    gt_path = pickle_g_dir +  "/gt/" + binname + ".p3"
    ddisasm_path = pickle_g_dir + "/ddisasm/" + binname + ".p3"
    ramblr_path = pickle_g_dir + "/ramblr/" + binname + ".p3"
    retro_path = pickle_g_dir + "/retro_sym/" + binname + ".p3"
    
    prog_c = pickle.load(open(gt_path, 'rb'))
    addrs = []
    for instr_addr in prog_c.Instrs:
        instr = prog_c.Instrs[instr_addr]
        for idx, cmpt in enumerate(instr.Components):
            if cmpt.is_composite():
                lbl_addr = cmpt.Terms[0].Address
                const = cmpt.Terms[1]
                if prog_c.get_section(lbl_addr) != prog_c.get_section(lbl_addr + const):
                    addrs.append((idx, instr_addr, const))
    print('tt ', len(addrs))
    total_cnt += len(addrs)
    if os.path.exists(ddisasm_path):
        prog_r = pickle.load(open(ddisasm_path, 'rb'))
        for idx, addr, const in addrs:
            try:
                terms = prog_r.Instrs[addr].Components[idx].Terms
                if len(terms) == 2:
                    if terms[-1] == const:
                        print('TP')
                if len(terms) == 0:
                    print('FN')
            except:
                pass

if __name__ == '__main__':
    paths = []
    for line in open("/tmp/bbbig"):
        paths.append(line)

    p = multiprocessing.Pool(64)
    p.map(run, paths)
