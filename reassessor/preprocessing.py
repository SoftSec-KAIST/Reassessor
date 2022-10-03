from abc import abstractmethod
import os, sys
from elftools.elf.elffile import ELFFile

useless_sections = ['.rel.init', '.rel.text', '.rel.fini', '.rel.rodata', '.rel.eh_frame',
                    '.rel.init_array', '.rel.fini_array', '.rel.debug_aranges', '.rel.debug_info',
                    '.rel.debug_loc', '.rel.debug_ranges',  '.rel.data.rel.ro', '.rel.data',
                    '.rel.debug_line', '.data.rel.rodata',  '.rela.init', '.rela.text',
                    '.rela.fini', '.rela.rodata', '.rela.eh_frame', '.rela.init_array',
                    '.rela.fini_array', '.rela.debug_aranges', '.rela.debug_info', '.rela.debug_loc',
                    '.rela.debug_ranges',  '.rela.data.rel.ro', '.rela.data', '.rela.debug_line',
                    '.data.rela.rodata',  '.rand']

def remove_useless_sections(binary):
    for section in useless_sections:
        os.system('objcopy --remove-section %s %s'%(section, binary))

def copy_and_strip(target, binary, strip_binary):
    os.system('cp %s %s'%(target, binary))
    remove_useless_sections(binary)
    os.system('cp %s %s'%(binary, strip_binary))
    os.system('strip %s'%(strip_binary))





class Preprocessing:
    def __init__(self, target, output_dir):
        self.target =  os.path.abspath(target)
        self.output_dir =  os.path.abspath(output_dir)
        self.reassem_dir =  '%s/reassem'%(self.output_dir)

        #copy bin & strip binary
        self.base_name = os.path.basename(self.target)
        self.binary = '%s/bin/%s'%(self.output_dir, self.base_name)
        self.strip  = '%s/stripbin/%s'%(self.output_dir, self.base_name)

        self.retrowrite_output = ''
        self.ramblr_output = ''
        self.ddisasm_output = ''


    def run(self, bRamblr=True, bRetro=True, bDdisasm=True, reset=False):
        os.system('mkdir -p %s/bin'%(self.output_dir))
        os.system('mkdir -p %s/stripbin'%(self.output_dir))

        copy_and_strip(self.target, self.binary, self.strip)

        os.system('mkdir -p %s/reassem'%(self.output_dir))

        #create reassembly files
        if bRamblr:
            ramblr = Ramblr(self.strip, self.reassem_dir)
            self.ramblr_output = ramblr.reassembly(reset)

        if bRetro:
            retro = RetroWrite(self.binary, self.reassem_dir)
            self.retrowrite_output = retro.reassembly(reset)

        if bDdisasm:
            ddisasm = Ddisasm(self.strip, self.reassem_dir)
            self.ddisasm_output = ddisasm.reassembly(reset)



class Reassembly:
    def __init__(self, binary, output_dir):
        f = open(binary, 'rb')
        self.elffile = ELFFile(f)
        self.arch   = self.check_arch()
        self.pie    = self.check_pie()

        self.target = binary
        self.base_name = os.path.basename(binary)
        self.output_dir = output_dir

    def check_arch(self):
        if self.elffile['e_machine'] in ('EM_386', 'EM_486'):
            return 'x86'
        elif self.elffile['e_machine'] in ('EM_X86_64'):
            return 'x64'
        assert False, 'Unknown architecture'

    def check_pie(self):
        if self.elffile.header['e_type'] in ('ET_DYN'):
            return 'pie'
        if self.elffile.header['e_type'] in ('ET_EXEC'):
            return 'nopie'
        assert False, 'Unknown file type'

    def run_cmd(self, cmd, output=''):
        print('[+] ' + cmd)
        sys.stdout.flush()
        os.system(cmd)
        if output and os.path.exists(output):
            return output
        return ''

    @abstractmethod
    def reassembly(self, reset=False):
        pass


class Ramblr(Reassembly):
    def reassembly(self, reset=False):
        if self.pie != 'nopie':
            return ''

        reassem_output = '%s/ramblr.s'%(self.output_dir)
        if not reset and os.path.exists(reassem_output):
            return reassem_output

        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/ramblr:64d1049 sh -c "/root/ramblr.sh /input/%s /output/ramblr"'%(os.path.dirname(self.target), self.output_dir, self.base_name)
        self.run_cmd(cmd, reassem_output)
        if os.path.exists(reassem_output):
            return reassem_output
        return ''

class RetroWrite(Reassembly):
    def reassembly(self, reset=False):
        if self.arch != 'x64' or self.pie != 'pie':
            return ''

        reassem_output = '%s/retrowrite.s'%(self.output_dir)
        if not reset and os.path.exists(reassem_output):
            return reassem_output

        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/retrowrite:613562 sh -c "/root/retrowrite.sh /input/%s /output/retrowrite.s"'%(os.path.dirname(self.target), self.output_dir, self.base_name)
        self.run_cmd(cmd, reassem_output)
        if os.path.exists(reassem_output):
            return reassem_output

        return ''

class Ddisasm(Reassembly):
    def reassembly(self, reset=False):
        reassem_output = '%s/ddisasm.s'%(self.output_dir)
        if not reset and os.path.exists(reassem_output):
            return reassem_output

        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/ddisasm:1.5.3 sh -c "ddisasm --debug /input/%s --asm /output/ddisasm.s"'%(os.path.dirname(self.target), self.output_dir, self.base_name)
        self.run_cmd(cmd, reassem_output)
        if os.path.exists(reassem_output):
            return reassem_output
        return ''

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('target', type=str, help='Target Binary')
    parser.add_argument('output_dir', type=str, help='output_dir')
    parser.add_argument('--no-ramblr', dest='ramblr', action='store_false', help='Do not run ramblr')
    parser.add_argument('--no-retrowrite', dest='retrowrite', action='store_false', help='Do not run retrowrite')
    parser.add_argument('--no-ddisasm', dest='ddisasm', action='store_false', help='Do not run ddisasm')

    args = parser.parse_args()

    preprocessing = Preprocessing(args.target, args.output_dir)
    preprocessing.run(bRamblr=args.ramblr, bRetro=args.retrowrite, bDdisasm=args.ddisasm)
    '''
    if args.ramblr:
        ramblr = Ramblr(args.target, args.output_dir)
        ramblr.reassembly()
    if args.retrowrite:
        retrowrite = RetroWrite(args.target, args.output_dir)
        retrowrite.reassembly()
    if args.ddisasm:
        ddisasm = Ddisasm(args.target, args.output_dir)
        ddisasm.reassembly()
    '''
