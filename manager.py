import argparse
import os
import pickle
from mapper.collect_loc_candidates import collect_loc_candidates
from mapper.match_src_to_bin import match_src_to_bin

from normalizer.match_gt import normalize_gt

class manager:
    def __init__(self, bench_dir, composite_root, work_dir, sub_dir, bin_list):
        self.bench_dir = bench_dir

        self.asm_dir = os.path.join(bench_dir, sub_dir) + '/asm'
        self.bin_dir = os.path.join(bench_dir, sub_dir) + '/bin'

        self.composite_dir = os.path.join(composite_root, sub_dir)

        self.save_dir = os.path.join(work_dir, sub_dir) + '/gt'

        self.bin_list = bin_list

    def do(self, stages):
        for bin_name in self.bin_list:
            self.run(stages, bin_name)

    def get_bin_path(self, bin_name):
        return self.bin_dir + '/' + bin_name

    def get_composite_path(self):
        return self.composite_dir

    def save_gt(self, bin_name, gt):
        save_path = self.save_dir + '/' + bin_name + '.p3'
        os.system('mkdir -p %s'%(self.save_dir))
        print(save_path)
        with open(save_path, 'wb') as f:
            pickle.dump(gt, f)

    def get_asm_path(self, bin_name):
        return self.asm_dir


    def run(self, stages, bin_name):

        bench_dir = self.bench_dir
        bin_path = self.get_bin_path(bin_name)

        if 1 in stages:
            print('preprocessing')
            asm_path = self.get_asm_path(bin_name)
            func_dict = collect_loc_candidates(bench_dir, asm_path)
            bin2src_dict = match_src_to_bin(bench_dir, func_dict, bin_path)
        if 2 in stages:
            print('address mapping')
            composite_dir = self.get_composite_path()
            gt = normalize_gt(bench_dir, bin_path, bin2src_dict, composite_dir)
            self.save_gt(bin_name, gt)

        if 3 in stages:
            print('normalizer')
        if 4 in stages:
            print('differ')

def main(stages, bench_dir, composite_root, work_dir):
    run(stages, bench_dir, composite_root, work_dir, 'coreutils-8.30/x86/gcc/nopie/os-gold')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('bench', type=str, help='benchmark dir')
    parser.add_argument('composite', type=str, help='composite dir')
    parser.add_argument('work', type=str, help='work dir')
    parser.add_argument('--stages', nargs='*', type=int,
                        help='set stage')

    args = parser.parse_args()
    print(args.stages)

    sub_dir =  'coreutils-8.30/x86/gcc/nopie/os-gold'
    bin_list = ['ls']

    mgr = manager(args.bench, args.composite, args.work, sub_dir, bin_list)

    mgr.do(set(args.stages))

