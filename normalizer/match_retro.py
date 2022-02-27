import re
import capstone
from capstone.x86 import *
import sys
import os
import pickle

# FIXME: clean up later
RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')

from lib.asm_types import *
from normalizer.match_tool import NormalizeTool, parse_att_asm_line

class NormalizeRetro(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, retro_map_func, retro_label_to_addr, capstone.CS_OPT_SYNTAX_ATT)

def retro_label_to_addr(label):
    if label.startswith('.LC'):
        addr = int(label[3:], 16)
    elif label.startswith('.L'):
        addr = int(label[2:], 16)
    else:
        addr = 0
    return addr

def retro_map_func(reassem_path):
    with open(reassem_path) as f:
        addressed_asms = []
        addressed_data = []
        addr = -1
        for idx, line in enumerate(f):
            line = line.rstrip()
            if line.startswith('.L') and line.endswith(':'):
                line = line.split(':')[0]
                if line.startswith('.LC'):
                    addr = int(line[3:], 16)
                elif line.startswith('.L'):
                    addr = int(line[2:], 16)
            elif RE_INST.match(line):
                tokens = parse_att_asm_line(line)
                if len(tokens) > 0:
                    addressed_asms.append((addr, tokens, idx))
            elif line.strip().startswith('.long'):
                token = line.split('.long')[1]
                addressed_data.append((addr, token, 4, idx))
            elif line.strip().startswith('.quad'):
                token = line.split('.quad')[1]
                addressed_data.append((addr, token, 8, idx))

    return addressed_asms, addressed_data


if __name__ == '__main__':
    bin_path = sys.argv[1]
    reassem_path = sys.argv[2]
    pickle_path = sys.argv[3]

    retro = NormalizeRetro(bin_path, reassem_path)
    retro.normalize_inst()
    retro.normalize_data()

    with open(pickle_path, 'wb') as f:
        pickle.dump(retro.prog, f)



