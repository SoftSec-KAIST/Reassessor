from elftools.elf.elffile import ELFFile
import os, sys
from .preprocessing.strip import copy_and_strip
from .normalizer.gt import NormalizeGT
from .normalizer.ramblr import NormalizeRamblr
from .normalizer.retro import NormalizeRetro
from .normalizer.ddisasm import NormalizeDdisasm
from .differ.diff import diff

class Reassessor:
    def __init__(self, target, assem_dir, output_dir):
        f = open(target, 'rb')
        self.elffile = ELFFile(f)
        self.target =  os.path.abspath(target)
        self.assem_dir  =  os.path.abspath(assem_dir)
        self.output_dir =  os.path.abspath(output_dir)
        self.arch   = self.check_arch()
        self.pie    = self.check_pie()

        #copy bin & strip binary
        self.base_name = os.path.basename(self.target)
        self.binary = '%s/bin/%s'%(self.output_dir, self.base_name)
        self.strip  = '%s/stripbin/%s'%(self.output_dir, self.base_name)

        self.retrowrite_output = ''
        self.ramblr_output = ''
        self.ddisasm_output = ''

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

    def preprocessing(self):
        os.system('mkdir -p %s/bin'%(self.output_dir))
        os.system('mkdir -p %s/stripbin'%(self.output_dir))
        #os.system('./preprocessing/strip.sh %s %s %s'%(self.target, self.binary, self.strip))
        copy_and_strip(self.target, self.binary, self.strip)

        os.system('mkdir -p %s/reassem'%(self.output_dir))
        #create reassembly files
        self.retrowrite_output = self.run_retrowrite()

        self.ramblr_output = self.run_ramblr()

        self.ddisasm_output = self.run_ddisasm()

    def run_cmd(self, cmd, output=''):
        print('[+] ' + cmd)
        sys.stdout.flush()
        os.system(cmd)
        if output and os.path.exists(output):
            return output
        return ''

    def run_retrowrite(self):
        if self.arch != 'x64' or self.pie != 'pie':
            return ''

        reassem_output = '%s/reassem/retrowrite.s'%(self.output_dir)
        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/retrowrite:613562 sh -c "/root/retrowrite.sh /input/%s /output/reassem/retrowrite.s"'%(os.path.dirname(self.binary), self.output_dir, self.base_name)
        return self.run_cmd(cmd, reassem_output)

    def run_ramblr(self):
        if self.pie != 'nopie':
            return ''

        reassem_output = '%s/reassem/ramblr.s'%(self.output_dir)
        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/ramblr:64d1049 sh -c "/root/ramblr.sh /input/%s /output/reassem/ramblr"'%(os.path.dirname(self.strip), self.output_dir, self.base_name)
        return self.run_cmd(cmd, reassem_output)


    def run_ddisasm(self):

        reassem_output = '%s/reassem/ddisasm.s'%(self.output_dir)
        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/ddisasm:1.5.3 sh -c "ddisasm --debug /input/%s --asm /output/reassem/ddisasm.s"'%(os.path.dirname(self.strip), self.output_dir, self.base_name)
        return self.run_cmd(cmd, reassem_output)


    def run_normalizer(self):
        norm_dir = '%s/norm_db'%(self.output_dir)
        os.system('mkdir -p %s'%(norm_dir))
        gt_norm_path = '%s/gt.db'%(norm_dir)
        print('python3 -m normalizer.gt %s %s %s --reloc %s'%(self.binary, self.assem_dir, gt_norm_path, self.target))
        gt = NormalizeGT(self.binary, self.assem_dir, self.target)
        gt.normalize_data()
        gt.save(gt_norm_path)
        self.gt_norm = gt_norm_path

        self.retrowrite_norm = ''
        self.ramblr_norm = ''
        self.ddisasm_norm = ''

        if self.retrowrite_output:
            norm_path = '%s/retrowrite.db'%(norm_dir)
            print('python3 -m normalizer.retro %s %s %s'%(self.binary, self.retrowrite_output, norm_path))
            retrowrite = NormalizeRetro(self.binary, self.retrowrite_output)
            retrowrite.normalize_inst()
            retrowrite.normalize_data()
            retrowrite.save(norm_path)
            self.retrowrite_norm = norm_path
        if self.ramblr_output:
            norm_path = '%s/ramblr.db'%(norm_dir)
            print('python3 -m normalizer.ramblr %s %s %s'%(self.binary, self.ramblr_output, norm_path))
            ramblr = NormalizeRamblr(self.binary, self.ramblr_output)
            ramblr.normalize_inst()
            ramblr.normalize_data()
            ramblr.save(norm_path)
            self.ramblr_norm = norm_path
        if self.ddisasm_output:
            norm_path = '%s/ddisasm.db'%(norm_dir)
            print('python3 -m normalizer.ddisasm %s %s %s'%(self.binary, self.ddisasm_output, norm_path))
            ddisasm = NormalizeDdisasm(self.binary, self.ddisasm_output)
            ddisasm.normalize_inst()
            ddisasm.normalize_data()
            ddisasm.save(norm_path)
            self.ddisasm_norm = norm_path

    def run_differ(self):
        norm_dict = dict()
        error_dir = '%s/errors'%(self.output_dir)
        cmd = 'python3 -m differ.diff %s %s %s'%(self.binary, self.gt_norm, error_dir)
        if self.retrowrite_norm:
            cmd += ' --retro %s'%(self.retrowrite_norm)
            norm_dict['retrowrite'] = self.retrowrite_norm
        if self.ramblr_norm:
            cmd += ' --ramblr %s'%(self.ramblr_norm)
            norm_dict['ramblr'] = self.ramblr_norm
        if self.ddisasm_norm:
            cmd += ' --ddisasm %s'%(self.ddisasm_norm)
            norm_dict['ddisasm'] = self.ddisasm_norm

        print(cmd)

        diff(self.binary, self.gt_norm, norm_dict, error_dir)

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('target', type=str, help='Target Binary')
    parser.add_argument('assem_dir', type=str, help='Assembly Directory')
    parser.add_argument('output_dir', type=str, help='output_dir')

    parser.add_argument('--no-preprocessing', dest='preprocessing', action='store_false')
    parser.add_argument('--ramblr', type=str, help='ramblr output')
    parser.add_argument('--retrowrite', type=str, help='retrowrite output')
    parser.add_argument('--ddisasm', type=str, help='ddisasm output')
    args = parser.parse_args()

    reassessor = Reassessor(args.target, args.assem_dir, args.output_dir)
    if args.preprocessing:
        reassessor.preprocessing()
    else:
        self.retrowrite_output = args.retrowrite
        self.ramblr_output = args.ramblr
        self.ddisasm_output = args.ddisasm

    reassessor.run_normalizer()
    reassessor.run_differ()

