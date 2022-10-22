import re
import capstone
import os
from .tool_base import NormalizeTool
from reassessor.lib.parser import parse_att_asm_line, ReasmLabel, parse_set_directive
from bitstring import BitArray

HUGE_FILE_SIZE = 1024*1024*1024*10
HUGE_BIT_ARRAY = 0x50000000

class NormalizeRetro(NormalizeTool):
    def __init__(self, bin_path, reassem_path, supplement_file=''):
        super().__init__(bin_path, reassem_path, retro_mapper, capstone.CS_OPT_SYNTAX_ATT, label_func = retro_label_func, supplement_file=supplement_file)

retro_huge_addr_set = BitArray(1)

def retro_label_to_addr(label):
    if label.startswith('.LC'):
        addr = int(label[3:], 16)
    elif label.startswith('.LLC'):
        addr = int(label[4:], 16)
    elif label.startswith('.L'):
        if '_' in label:
            addr = int(label.split('_')[-1],16)
        else:
            addr = int(label[2:], 16)
    else:
        addr = 0
    return addr

def retro_label_func(label):
    global retro_huge_addr_set
    addr = retro_label_to_addr(label)
    if HUGE_BIT_ARRAY > addr and addr > 0:
        if retro_huge_addr_set[addr]:
            return addr
    return 0

def retro_mapper(reassem_path, tokenizer, supplement_file):
    result = []
    addr = -1

    fsize = os.path.getsize(reassem_path)
    global retro_huge_addr_set

    if fsize > HUGE_FILE_SIZE:
        retro_huge_addr_set = BitArray(HUGE_BIT_ARRAY)

    with open(reassem_path, errors='ignore') as f:
        for idx, line in enumerate(f):
            terms = line.split('#')[0].split()
            if len(terms) == 0:
                continue
            if re.search('^.*:$', terms[0]):
                xaddr = retro_label_to_addr(terms[0][:-1])
                if xaddr > 0:
                    addr = xaddr

                if addr > 0:
                    #Too many labels might cause OOM errors
                    #We use bitarray to check existance of labels
                    if fsize > HUGE_FILE_SIZE:
                        if xaddr == addr:
                            retro_huge_addr_set.set(1, [addr])
                        else:
                            result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                    else:
                        result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                else:
                    result.append(ReasmLabel(terms[0][:-1], 0, idx+1))
                continue
            elif terms[0] in ['.long', '.quad']:
                expr = ''.join(terms[1:])
                #if re.search('.[+|-]', expr):
                if [term for term in re.split('[+|-]', expr) if re.match('[._a-zA-Z]', term) ]:
                    result.append(tokenizer.parse_data(terms[0] + ' ' + expr, addr, idx+1))
            elif terms[0] in ['.set']:
                # ex) .set FUN_804a3f0, . - 10
                # ex) .set L_0, 0
                label_addr, num = parse_set_directive(line, retro_label_to_addr)
                result.append(ReasmSetLabel(terms[1][:-1], label_addr, num, idx+1))
            elif re.search('^[a-zA-Z].*', terms[0]):
                asm_line = ' '.join(terms)
                result.append(tokenizer.parse(asm_line, addr, idx+1))
            else:
                continue
            addr = -1

    return result




import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_gt')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('reassem_path', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    retro = NormalizeRetro(args.bin_path, args.reassem_path)
    retro.normalize_inst()
    retro.normalize_data()
    retro.save(args.save_file)

