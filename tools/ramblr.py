from manager import Manager, REConf
import os
import glob

def ramblr_cmd(conf):
    cmd_list = []

    bfile = '%s/%s/stripbin/%s'%(conf.bench, conf.sub_dir, conf.filename)
    rfile = '%s/%s/%s/%s'%(conf.tool_path, conf.sub_dir, conf.tool_name, conf.filename)

    cmd1 = 'mkdir -p %s'%(os.path.dirname(rfile))
    cmd_list.append(cmd1)
    cmd2 = 'python3 ramblr.py %s %s'%(bfile, rfile)
    cmd_list.append(cmd2)
    return cmd_list

class Ramblr(Manager):
    def __init__(self, core, bench='/data3/1_reassessor/benchmark', tool_path='/data3/1_reassessor/new_ramblr', tool_name='ramblr'):
        super().__init__(core, bench, tool_path, tool_name)

    def gen_option(self, work_dir, tool_name):
        ret = []
        for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            for arch in ['x64', 'x86']:
                #for comp in ['clang', 'gcc']:
                for comp in ['gcc']:
                    #for popt in ['nopie', 'pie']:
                    for popt in ['nopie']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                for binary in glob.glob('%s/%s/bin/*'%(work_dir, sub_dir)):
                                    filename = os.path.basename(binary)

                                    ret.append(REConf(self.bench, tool_name, self.tool_path, sub_dir, filename, arch, comp, popt, lopt, ramblr_cmd))
        return ret


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    args = parser.parse_args()

    mgr = Ramblr(args.core)
    mgr.print_conf()
    #mgr.run()

    mgr.print_compile_cmd()
    #mgr.compile()

