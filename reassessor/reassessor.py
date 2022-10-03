import os, sys
from .normalizer.gt import NormalizeGT
from .normalizer.ramblr import NormalizeRamblr
from .normalizer.retro import NormalizeRetro
from .normalizer.ddisasm import NormalizeDdisasm
from .differ.diff import diff
from .preprocessing import remove_useless_sections

class Reassessor:
    def __init__(self, target, assem_dir, output_dir, build_path):
        self.target =  os.path.abspath(target)
        self.assem_dir  =  os.path.abspath(assem_dir)
        self.output_dir =  os.path.abspath(output_dir)
        self.build_path = os.path.abspath(build_path)

        #copy binary
        self.base_name = os.path.basename(self.target)
        self.binary = '%s/bin/%s'%(self.output_dir, self.base_name)
        if not os.path.exists(self.binary):
            os.system('mkdir -p %s/bin'%(self.output_dir))
            os.system('cp %s %s'%(self.target, self.binary))
            remove_useless_sections(self.binary)

        self.retrowrite_output = ''
        self.ramblr_output = ''
        self.ddisasm_output = ''

        self.retrowrite_norm = ''
        self.ramblr_norm = ''
        self.ddisasm_norm = ''


    def run_normalizer(self):
        norm_dir = '%s/norm_db'%(self.output_dir)
        os.system('mkdir -p %s'%(norm_dir))
        gt_norm_path = '%s/gt.db'%(norm_dir)
        print('python3 -m normalizer.gt %s %s %s --reloc %s --build_path %s'%(self.binary, self.assem_dir, gt_norm_path, self.target, self.build_path))
        gt = NormalizeGT(self.binary, self.assem_dir, build_path=self.build_path, reloc_file=self.target)
        gt.normalize_data()
        gt.save(gt_norm_path)
        self.gt_norm = gt_norm_path

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


def wrapper(target, output_dir):
    preproc = Preprocessing(target, output_dir)
    preproc.run()


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('target', type=str, help='Target Binary')
    parser.add_argument('assem_dir', type=str, help='Assembly Directory')
    parser.add_argument('output_dir', type=str, help='output_dir')
    parser.add_argument('build_path', type=str, help='build_path')

    parser.add_argument('--no-preprocessing', dest='preprocessing', action='store_false')
    parser.add_argument('--ramblr', type=str, help='ramblr output')
    parser.add_argument('--retrowrite', type=str, help='retrowrite output')
    parser.add_argument('--ddisasm', type=str, help='ddisasm output')
    args = parser.parse_args()

    reassessor = Reassessor(args.target, args.assem_dir, args.output_dir, args.build_path)
    if args.ramblr:
        reassessor.ramblr_output = args.ramblr
    if args.retrowrite:
        reassessor.retrowrite_output = args.retrowrite
    if args.ddisasm:
        reassessor.ddisasm_output = args.ddisasm
    reassessor.run_normalizer()
    reassessor.run_differ()

