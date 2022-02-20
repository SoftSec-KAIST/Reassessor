import re
import capstone
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import sys

from lib.asm_types import *
from lib.utils import *
#from lib.parser import parse_att_components
from normalizer.match_tool import NormalizeTool, get_data_size, DATA_DIRECTIVE, SKIP_DIRECTIVE
import pickle

RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')


class NormalizeRamblr(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, ramblr_map_func, ramblr_label_to_addr, capstone.CS_OPT_SYNTAX_ATT)
    '''
    def parse_label(self, s, v):
        if is_gotoff(s):
            print('Ramblr cannot support x86 PIE')
            print(s)
            #sys.exit(-1)
        else:
            if s in self.relocs:
                v = self.relocs[s]
                return Label(s, LblTy.LABEL, v)
            elif s.startswith('.label') or s.startswith('label') or s.startswith('sub'):
                v = int(s.split('_')[1], 16)
                return Label(s, LblTy.LABEL, v)
            else:
                #import pdb
                #pdb.set_trace()
                return Label(s, LblTy.LABEL, v)
    def has_label(self, s):
        if s:
             return (s in self.relocs) or s.startswith('.label') or s.startswith('label') or s.startswith('sub')
        return False
    '''

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

            #if addr in [0x8049d82]:
            #    import pdb
            #    pdb.set_trace()

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
    addressed_lines = mapper(reassem_path)

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
            tokens = parse_ramblr_asm_line(line)
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


def parse_ramblr_asm_line(line):
    src_inst = line
    if src_inst.startswith('nop'):
        return []
    if '\t' in src_inst:
        src_inst = src_inst.split('\t', 1)
        src_inst[1] = src_inst[1].split(',')
    else:
        src_inst = [src_inst, []]
    for i in range(len(src_inst[1])):
        src_inst[1][i] = src_inst[1][i].strip()
    return src_inst


if __name__ == '__main__':
    bin_path = sys.argv[1]
    reassem_path = sys.argv[2]
    pickle_path = sys.argv[3]

    ramblr = NormalizeRamblr(bin_path, reassem_path)
    ramblr.normalize_inst()
    ramblr.normalize_data()

    with open(pickle_path, 'wb') as f:
        pickle.dump(ramblr.prog, f)
