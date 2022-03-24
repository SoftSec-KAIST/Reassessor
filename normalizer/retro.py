import re
import capstone

from normalizer.tool_base import NormalizeTool
from lib.parser import parse_att_asm_line, ReasmLabel

class NormalizeRetro(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, retro_mapper, retro_label_to_addr, capstone.CS_OPT_SYNTAX_ATT)

def retro_label_to_addr(label):
    if label.startswith('.LC'):
        addr = int(label[3:], 16)
    elif label.startswith('.L'):
        if '_' in label:
            addr = int(label.split('_')[-1],16)
        else:
            addr = int(label[2:], 16)
    else:
        addr = 0
    return addr

def retro_mapper(reassem_path, tokenizer):
    result = []
    addr = -1
    with open(reassem_path, errors='ignore') as f:
        for idx, line in enumerate(f):
            terms = line.split('#')[0].split()
            if len(terms) == 0:
                continue
            if re.search('^.*:$', terms[0]):
                xaddr = retro_label_to_addr(terms[0][:-1])
                if xaddr > 0:
                    addr = xaddr
                elif addr > 0:
                    result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                continue
            elif terms[0] in ['.long', '.quad']:
                expr = ''.join(terms[1:])
                #if re.search('.[+|-]', expr):
                if [term for term in re.split('[+|-]', expr) if re.match('[._a-zA-Z]', term) ]:
                    result.append(tokenizer.parse_data(terms[0] + ' ' + expr, addr, idx+1))
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

