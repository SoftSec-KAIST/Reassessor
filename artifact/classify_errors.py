from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

black_list = []


BuildConf = namedtuple('BuildConf', ['cmd','output'])
global_no = 0

def gen_option(output_root):
    ret = []
    global global_no
    for tool in ['ramblr', 'retrowrite', 'ddisasm']:
        for arch in ['x86', 'x64']:
            for popt in ['pie', 'nopie']:
                if tool in ['ramblr'] and popt in ['pie']:
                    continue

                if tool in ['retrowrite'] and (popt in ['nopie'] or arch in ['x86']):
                    continue

                for err in ['E1','E2','E3','E4','E5','E6','E7','E8']:
                    output = 'triage/%s/%s/%s/%sFP.txt'%(tool, arch, popt, err)
                    cmd = "grep '^%sFP' %s/*/%s/*/%s/*/*/errors/%s/sym_diff.txt > %s "%(
                        err, output_root, arch, popt, tool, output)

                    ret.append(BuildConf(cmd,output))

                    if err == 'E8':
                        continue

                    output = 'triage/%s/%s/%s/%sFN.txt'%(tool, arch, popt, err)
                    cmd = "grep '^%sFN' %s/*/%s/*/%s/*/*/errors/%s/sym_diff.txt > %s "%(
                        err, output_root, arch, popt, tool, output)


                    ret.append(BuildConf(cmd,output))

                output = 'triage/%s/%s/%s/DisassemErr.txt'%(tool, arch, popt)
                cmd = "grep '^0x' %s/*/%s/*/%s/*/*/errors/%s/disasm_diff.txt > %s "%(
                        output_root, arch, popt, tool, output)
                ret.append(BuildConf(cmd,output))
    return ret


def job(conf):
    os.system('mkdir -p %s'%(os.path.dirname(conf.output)))
    os.system(conf.cmd)

class Manager:
    def __init__(self, input_root='./dataset', output_root='./output'):
        self.config_list = gen_option(output_root)


    def run(self, core=1):
        if core and core > 1:
            p = multiprocessing.Pool(core)
            p.map(job, self.config_list)
        else:
            for conf in self.config_list:
                job(conf)


import argparse
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--skip', action='store_true')

    args = parser.parse_args()

    mgr = Manager(output_root='./output')

    if not args.skip:
        os.system('mkdir -p ./triage')
        if args.core:
            mgr.run(args.core)
        else:
            mgr.run()


