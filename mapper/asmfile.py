import re
from collections import namedtuple
DATA_DIRECTIVE = ['.byte', '.asciz', '.quad', '.ascii', '.long', '.short']

AsmInst = namedtuple('AsmInst', ['opcode', 'operands', 'idx'])
LocInfo = namedtuple('LocInfo', ['path', 'idx'])

class CompositeData:
    def __init__(self, label, members):
        self.label = label
        self.members = members
        self.addr = ''

    def set_addr(self, addr):
        self.addr = addr

class AsmFileInfo:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(self.file_path) as fp:
            self.lines = fp.readlines()
        self.idx = -1
        self.func_dict = dict()
        self.composite_data = dict()
        self.jmp_dict = dict()
        self.debug_loc_paths = dict()
        self.section = 'none'

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

            if data.startswith('.file '):
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
        while self.mov_next():
            terms = self.get_line().split()
            if terms[0] in DATA_DIRECTIVE:
                members.append((self.get_line(), self.idx))
                if terms[0] in ['.long', '.quad']:
                    if re.search('.[+|-]', terms[1]):
                        bHasComposite =  True
            else:
                break
            #if self.is_section_directive(terms):
            #    break
        if bHasComposite:
            #print(label)
            #for mem in members:
            #    print(mem)

            self.composite_data[label] = CompositeData(label, members)

        return {}

    def is_func_label(self, terms):
        if self.section in ['text']:
            if re.search('^[_a-zA-Z].*:', terms[0]):
                return True
        return False

    def getJmpEntries(self):
        label = ''
        jmp_entries = []
        while self.mov_next():
            terms = self.get_line().split()
            if re.search('.L.*:', terms[0]):
                label = terms[0][:-1]
                break

        while self.mov_next():
            terms = self.get_line().split()
            if terms[0] not in ['.long', '.quad']:
                break
            jmp_entries.append(self.get_line())

        if jmp_entries:
            self.jmp_dict[label] = CompositeData(label, jmp_entries)

        return {}

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

            inst_list.append(AsmInst(opcode, self.parse_att_operands(operand), idx))

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
        while self.mov_next():
            terms = self.get_line().split()

            if terms[0] in ['.size'] :
                if terms[1][:-1] in [func_name]:
                    #print(self.get_line())
                    break

            if self.is_section_directive(terms) and self.section in ['data']:
                continue
            elif re.search('^[a-zA-Z]', terms[0]):
                inst_list.extend(self.parse_inst(self.get_line(), self.idx))
            elif terms[0] in ['.loc']:
                inst_list.append(self.get_loc_info(terms))

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

    def xxx(self):
        for i in range(100):
            if line.startswith(".L"):
                have_label = True
                label_name.append(line.split(":")[0])
            elif RE_INST.match(line):
                if have_label:
                    #if not is_semantically_nop_str(line):
                    labels.append((label_name, idx + base_idx))
                    label_name = []
                    have_label = False
                    #else:
                    #    print(line.strip(), file = sys.stderr)
                if is_rep:
                    '''
                    From:
                        rep(e)
                        stosb ...
                    To:
                        rep(e) stosb ...
                    '''
                    is_rep = False
                    inst_split = line.split("# ")[0].strip().split("\t")
                    opcode += " " + inst_split[0]
                    if len(inst_split) > 1:
                        operands = inst_split[1].split(", ")
                    else:
                        operands = []
                    result.append([opcode, operands, idx - 1 + base_idx])
                    continue
                #if is_semantically_nop_str(line):
                #    continue
                if "cld; rep" in line:
                    '''
                    From:
                        cld; rep; movsb
                    To:
                        cld
                        rep movsb
                    '''
                    result.append(["cld", [], idx + base_idx])
                    result.append(["rep " + line.split("; ")[-1], [], idx + base_idx])
                    continue

                inst_split = line.split("# ")[0].strip().split("\t")
                opcode = inst_split[0]
                if len(inst_split) > 1:
                    operands = inst_split[1].split(", ")
                else:
                    operands = []
                    if opcode.startswith("rep;") or opcode.startswith("repe;"):
                        '''
                        rep;stosb\x20...
                        rep;movsb\x20...
                        '''
                        inst_split = opcode.split(" ", 1)
                        opcode = inst_split[0]
                        if len(inst_split) > 1:
                            operands = inst_split[1].split(", ")
                        else:
                            operands = []
                    elif opcode.startswith("rep") and " " in opcode.strip():
                        operands = []
                    elif opcode.startswith("rep"):
                        is_rep = True
                        continue
                if is_gcc_switch(opcode, operands, lines[idx+1]):
                    lname, entries = get_switch_entries(lines[idx+2:], idx + 3 + base_idx)
                    jmptbl[lname] = JumpTable(entries)
                result.append([opcode, operands, idx + base_idx])




import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AsmFileInfo')
    parser.add_argument('file_path', type=str)
    args = parser.parse_args()

    asmfile = AsmFileInfo(args.file_path)

    amsfile.scan()
    #import pdb
    #pdb.set_trace()
    #print(args.file_path)



