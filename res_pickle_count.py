import sys, os
from utils import *

TOOLS = ['retro_sym', 'ramblr', 'ddisasm']

def main(bench_dir, pickle_dir):
    bins = {'x86pie': 0, 'x64pie': 0, 'x86nopie': 0, 'x64nopie': 0}
    gt = {'x86pie': 0, 'x64pie': 0, 'x86nopie': 0, 'x64nopie': 0}
    ddisasm = {'x86pie': 0, 'x64pie': 0, 'x86nopie': 0, 'x64nopie': 0}
    ramblr = {'x86pie': 0, 'x64pie': 0, 'x86nopie': 0, 'x64nopie': 0}
    retro = {'x86pie': 0, 'x64pie': 0, 'x86nopie': 0, 'x64nopie': 0}
    for package, arch, compiler, pie, opt in gen_options():
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        pickle_base_dir = os.path.join(pickle_dir, package, arch, compiler, pie, opt)
        for bin_name in os.listdir(bin_dir):
            bins[arch+pie] += 1
            pickle_gt_path = os.path.join(pickle_base_dir, 'gt', bin_name + '.p3')
            if os.path.exists(pickle_gt_path):
                gt[arch+pie] += 1
            else:
                print(pickle_gt_path)
            for tool in TOOLS:
                pickle_tool_path = os.path.join(pickle_base_dir, tool, bin_name + '.p3')
                if os.path.exists(pickle_tool_path):
                    if tool == 'retro_sym':
                        retro[arch+pie] += 1
                    elif tool == 'ramblr':
                        ramblr[arch+pie] += 1
                    elif tool == 'ddisasm':
                        ddisasm[arch+pie] += 1
    for arch in ['x86', 'x64']:
        for pie in ['pie', 'nopie']:
            print(arch + ' - ' + pie)
            print('%d | %d | %d | %d | %d |' % (bins[arch+pie], gt[arch+pie], ddisasm[arch+pie], ramblr[arch+pie], retro[arch+pie]))

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    pickle_dir = sys.argv[2]
    #pickle_dir = '/home/bbbig/tmp/pickles3'
    main(bench_dir, pickle_dir)
