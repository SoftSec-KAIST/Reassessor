import re
from collections import namedtuple
DATA_DIRECTIVE = ['.byte', '.asciz', '.quad', '.ascii', '.long', '.short', '.zero']

AsmInst = namedtuple('AsmInst', ['asm_line', 'opcode', 'operand_list', 'idx'])
LocInfo = namedtuple('LocInfo', ['path', 'idx'])

class CompositeData:
    def __init__(self, label, members, idx):
        self.label = label
        self.members = members
        self.addr = ''
        self.idx = idx

    def set_addr(self, addr):
        self.addr = addr

class AsmFileInfo:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(self.file_path, errors='ignore') as fp:
            self.lines = fp.readlines()
        self.idx = -1
        self.func_dict = dict()
        self.composite_data = dict()
        self.jmp_dict = dict()
        self.debug_loc_paths = dict()
        self.section = 'none'
        self.visited_func = set()

    def get_line(self):
        return self.lines[self.idx].split('#')[0]

    def mov_prev(self):
        if self.idx > 0:
            self.idx -= 1
            return True
        return False

    def mov_next(self):

        while self.idx+1 < len(self.lines):
            self.idx += 1
            data = self.get_line().strip()
            if len(data) == 0:
                continue
            if data.startswith('.file'):
                terms = data.split()
                if terms[1].isdigit():
                    fid = int(terms[1])
                    path = terms[-1][1:-1]
                    self.debug_loc_paths[fid] = path
                continue

            return True
        return False

    def is_section_directive(self, terms):
        if terms[0] in ['.text']:
            self.section = 'text'
            return True
        elif terms[0] in ['.data', '.bss']:
            self.section = 'data'
            return True
        elif terms[0] in ['.section']:
            if terms[1].startswith('.text'):
                self.section = 'text'
            elif terms[1].startswith('.rodata') or terms[1].startswith('.bss') or terms[1].startswith('.data'):
                self.section = 'data'
            elif terms[1].startswith('.gcc_except') or terms[1].startswith('.debug'):
                self.section = 'none'
            elif terms[1].startswith('.init_array') or terms[1].startswith('.fini_array'):
                self.section = 'none'
            elif '.note.GNU' in terms[1]:
                self.section = 'none'
            return True

        return False

    def get_loc_info(self, terms):
        assert terms[0] in ['.loc']
        fid = int(terms[1])
        no = int(terms[2])
        if fid not in self.debug_loc_paths:
            assert False, 'Could not get loc info'
        path = self.debug_loc_paths[fid]
        return LocInfo(path, no)

    def is_debug_directive(self, terms):
        if terms[0].startswith('.cfi'):
            return True

        return False

    def is_data_label(self, terms):
        if self.section in ['data']:
            if re.search('^[._a-zA-Z].*:', terms[0]):
                return True
        return False

    def get_composite_data(self, label):
        bHasComposite = False
        members = []
        idx = self.idx
        while self.mov_next():
            terms = self.get_line().split()
            if terms[0] in DATA_DIRECTIVE:
                if terms[0] in ['.long', '.quad']:
                    # if it has label-label patterns, it would be jump table
                    if not members and '@GOTOFF' in terms[1]:
                        self.mov_prev()
                        self.get_jmp_table(label)
                        return
                    if not members and re.search('-\.L', terms[1]):
                        self.mov_prev()
                        self.get_jmp_table(label)
                        return

                    if re.search('.[+|-]', terms[1]):
                        bHasComposite =  True
                members.append((self.get_line(), self.idx))
            else:
                self.mov_prev()
                break

        if bHasComposite:
            self.composite_data[label] = CompositeData(label, members, idx)


    def is_func_label(self, terms):
        if self.section in ['text']:
            if re.search('^[_a-zA-Z].*:', terms[0]):
                return True
        return False

    def get_jmp_table(self, label):
        jmp_entries = []
        idx = self.idx
        while self.mov_next():
            terms = self.get_line().split()
            if terms[0] not in ['.long', '.quad']:
                self.mov_prev()
                break
            jmp_entries.append((self.get_line(), self.idx))

        if jmp_entries:
            self.jmp_dict[label] = CompositeData(label, jmp_entries, idx)


    def parse_inst(self, inst_str, idx, rep_str=''):
        inst_str_list = inst_str.split(';')
        inst_list = []
        for inst_one in inst_str_list:
            terms = inst_one.split()
            opcode = terms[0]
            if opcode.startswith('rep'):
                if len(terms) == 1:
                    rep_str = opcode
                    continue
                else:
                    opcode = ' '.join(terms[:2])
                    operand = ' '.join(terms[2:])
            elif rep_str:
                opcode = rep_str + ' ' + opcode
                operand = ' '.join(terms[1:])
                rep_str = ''
            else:
                operand = ' '.join(terms[1:])

            inst_list.append(AsmInst('%s %s'%(opcode, operand), opcode, self.parse_att_operands(operand), idx))

        if rep_str:
            cur_idx = self.idx
            self.mov_next()
            inst_list.extend(self.parse_inst(self.get_line(), cur_idx, rep_str))

        return inst_list

    def parse_att_operands(self, operand_str):
        token = ''
        lpar = False
        operand_list = []
        for char in operand_str:
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



    def get_insts(self, func_name):
        inst_list = []
        label = ''
        while self.mov_next():
            terms = self.get_line().split()

            if terms[0] in ['.size'] :
                if terms[1][:-1] in [func_name]:
                    break
            # because of xxxx.cold @function
            elif terms[0] in ['.cfi_endproc']:
                break

            if self.is_section_directive(terms) and self.section in ['data']:
                pass
            elif re.search('^[a-zA-Z]', terms[0]):
                inst_list.extend(self.parse_inst(self.get_line(), self.idx))
            elif terms[0] in ['.loc']:
                inst_list.append(self.get_loc_info(terms))
            elif re.search('^\.L.*:$', terms[0]):
                label = terms[0][:-1]
                continue
            elif terms[0] in ['.long', '.quad'] and label:
                self.mov_prev()
                self.get_composite_data(label)
            else:
                continue

            label = ''

        self.func_dict[func_name] = inst_list


    def scan(self):

        while self.mov_next() :
            terms = self.get_line().split()

            if self.is_debug_directive(terms):
                continue
            elif self.is_section_directive(terms):
                continue
            elif self.is_func_label(terms):
                self.get_insts(terms[0][:-1])

            elif self.is_data_label(terms):
                self.get_composite_data(terms[0][:-1])



import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AsmFileInfo')
    parser.add_argument('file_path', type=str)
    args = parser.parse_args()

    asmfile = AsmFileInfo(args.file_path)

    amsfile.scan()



