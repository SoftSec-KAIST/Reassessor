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


    def run(self, reassem_dict):
        gt_norm_path, norm_dict = self.run_normalizer(reassem_dict)
        self.run_differ(gt_norm_path, norm_dict)


    def run_normalizer(self, reassem_dict, reset=False):
        norm_dir = '%s/norm_db'%(self.output_dir)
        os.system('mkdir -p %s'%(norm_dir))
        gt_norm_path = '%s/gt.db'%(norm_dir)
        print('python3 -m reassessor.normalizer.gt %s %s %s --reloc %s --build_path %s'%(self.binary, self.assem_dir, gt_norm_path, self.target, self.build_path))
        if os.path.exists(gt_norm_path) and not reset:
            pass
        else:
            gt = NormalizeGT(self.binary, self.assem_dir, build_path=self.build_path, reloc_file=self.target)
            gt.normalize_data()
            gt.save(gt_norm_path)

        norm_dict = dict()

        for tool, reassem_path in reassem_dict.items():
            reassem = None
            if tool == 'ramblr':
                norm_path = '%s/ramblr.db'%(norm_dir)
                print('python3 -m reassessor.normalizer.ramblr %s %s %s'%(self.binary, reassem_path, norm_path))
                reassem = NormalizeRamblr(self.binary, reassem_path)
            if tool == 'retrowrite':
                norm_path = '%s/retrowrite.db'%(norm_dir)
                print('python3 -m reassessor.normalizer.retro %s %s %s'%(self.binary, reassem_path, norm_path))
                reassem = NormalizeRetro(self.binary, reassem_path)
            if tool == 'ddisasm':
                norm_path = '%s/ddisasm.db'%(norm_dir)
                print('python3 -m reassessor.normalizer.ddisasm %s %s %s'%(self.binary, reassem_path, norm_path))
                reassem = NormalizeDdisasm(self.binary, reassem_path)

            if not os.path.exists(norm_path) or reset:
                reassem.normalize_inst()
                reassem.normalize_data()
                reassem.save(norm_path)

            if os.path.exists(norm_path):
                norm_dict[tool] = norm_path

        return gt_norm_path, norm_dict

    def run_differ(self, gt_norm_path, norm_dict):
        error_dir = '%s/errors'%(self.output_dir)
        cmd = 'python3 -m reassessor.differ.diff %s %s %s'%(self.binary, gt_norm_path, error_dir)
        if 'ramblr' in norm_dict:
            cmd += ' --ramblr %s'%(norm_dict['ramblr'])
        if 'retrowrite' in norm_dict:
            cmd += ' --retro %s'%(norm_dict['retrowrite'])
        if 'ddisasm' in norm_dict:
            cmd += ' --ddisasm %s'%(norm_dict['ddisasm'])

        print(cmd)

        diff(self.binary, gt_norm_path, norm_dict, error_dir)


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

    reassem_dict = dict()
    if args.ramblr:
        reassem_dict['ramblr'] = args.ramblr
    if args.retrowrite:
        reassem_dict['retrowrite'] = args.retrowrite
    if args.ddisasm:
        reassem_dict['ddisasm']  = args.ddisasm

    if reassem_dict:
        reassessor = Reassessor(args.target, args.assem_dir, args.output_dir, args.build_path)
        gt_norm_path, norm_dict = reassessor.run_normalizer(reassem_dict)
        reassessor.run_differ(gt_norm_path, norm_dict)

