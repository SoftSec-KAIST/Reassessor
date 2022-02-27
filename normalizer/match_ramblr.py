import re
import capstone
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import sys

from lib.asm_types import *
from lib.utils import *
from normalizer.match_tool import NormalizeTool, parse_att_asm_line
from normalizer.match_tool import DATA_DIRECTIVE, SKIP_DIRECTIVE
import pickle

RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')


class NormalizeRamblr(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, ramblr_map_func, ramblr_label_to_addr, capstone.CS_OPT_SYNTAX_ATT)

def ramblr_mapper(reassem_path):

    result = []
    addr = -1
    is_linker_gen = False
    with open(reassem_path) as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if line == '':
                continue

            if line.startswith('#'):
                addr_ = do_comment(line)
                if addr_ is not None:
                    addr = addr_
                continue

            token = line.split()[0]

            if token == '.section':
                section = line.split()[1]
                if section not in ['.fini', '.init', '.plt.got']:
                    is_linker_gen = False
                else:
                    is_linker_gen = True
                addr = -1
                continue

            if is_linker_gen or token in SKIP_DIRECTIVE:
                continue

            if line.startswith('sub_'):
                addr = int(re.findall('sub_(.*):', line)[0],16)

            assert addr > 0

            result.append((idx, addr, line))

            if token in DATA_DIRECTIVE:
                addr += get_data_size(line)
            elif line.endswith(':'):
                continue
            else:
                addr = -1

    return result

def ramblr_map_func(reassem_path):
    addressed_lines = ramblr_mapper(reassem_path)

    addressed_asms = []
    addressed_data = []
    for idx, addr, line in addressed_lines:
        tokens = line.split()
        if tokens[0] in DATA_DIRECTIVE:

           if tokens[0] in ['.quad', '.long']:

                exprs_str = ''.join(tokens[1:])

                if 'sub' in exprs_str or 'label' in exprs_str:
                    #exprs = re.split('\+|\-',exprs_str)

                    if tokens[0] == '.quad':
                        addressed_data.append((addr, exprs_str, 8, idx))
                    elif tokens[0] == '.long':
                        addressed_data.append((addr, exprs_str, 4, idx))
                    else:
                        print(line)
                        print('exit 3')
        else:
            tokens = parse_att_asm_line(line)
            if len(tokens) > 0:
                addressed_asms.append((addr, tokens, idx))

    return addressed_asms, addressed_data


def ramblr_label_to_addr(label):
    if label.startswith('sub_'):
        addr = int(label[4:], 16)
    else:
        addr = 0
    return addr

def do_comment(line):
    if line.startswith('#Procedure'):
        return None
    elif line.startswith('# 0x') and ':' in line:
        addr = int(line[2:].split(':')[0], 16)
        return addr
    elif line.startswith('# data @'):
        addr = int(line[8:], 16)
        return addr
    else:
        print(line)
        print('exit 1')
        #sys.exit(-1)

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


if __name__ == '__main__':
    bin_path = sys.argv[1]
    reassem_path = sys.argv[2]
    pickle_path = sys.argv[3]

    ramblr = NormalizeRamblr(bin_path, reassem_path)
    ramblr.normalize_inst()
    ramblr.normalize_data()

    with open(pickle_path, 'wb') as f:
        pickle.dump(ramblr.prog, f)
