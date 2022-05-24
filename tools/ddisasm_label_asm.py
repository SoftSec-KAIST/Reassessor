import os
import glob
import multiprocessing


class Ddisasm:
    def __init__(self, core, bench='/data3/1_reassessor/benchmark', tool_path1='/data3/1_reassessor/debug_dd', tool_path2='/data3/1_reassessor/new_ddisasm', tool_name='ddisasm', out_path='/data3/1_reassessor/debug_dd_expand'):
        self.core = core
        if core > 1:
            self.multi = True
        else:
            self.multi = False

        self.overwrite = False
        self.tool_path1=tool_path1
        self.tool_path2=tool_path2
        self.out_path = out_path
        self.conf_list = self.gen_option(bench, tool_name)

    def gen_option(self, work_dir, tool_name):
        ret = []
        for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            for arch in ['x64', 'x86']:
                #for comp in ['gcc' ]:
                for comp in ['clang', 'gcc' ]:
                    for popt in ['nopie', 'pie']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                for binary in glob.glob('%s/%s/bin/*'%(work_dir, sub_dir)):
                                    filename = os.path.basename(binary)

                                    asmfile1 = '%s/%s/%s/%s.s'%(self.tool_path1, sub_dir, tool_name, filename)
                                    if not os.path.isfile(asmfile1):
                                        continue

                                    asmfile2 = '%s/%s/%s/%s.s'%(self.tool_path2, sub_dir, tool_name, filename)
                                    if not os.path.isfile(asmfile2):
                                        continue

                                    out_path = '%s/%s/%s'%(self.out_path, sub_dir, tool_name)
                                    output1 = '%s/tmp1_%s.s'%(out_path, filename)
                                    output2 = '%s/tmp2_%s.s'%(out_path, filename)
                                    output3 = '%s/%s.s'%(out_path, filename)
                                    cmd0 = "mkdir -p %s"%(out_path)
                                    cmd1 = "grep '^\.L_.*:$' %s | sort > %s"%(asmfile1, output1)
                                    cmd2 = "grep '^\.L_.*:$' %s | sort > %s"%(asmfile2, output2)
                                    cmd3 = "comm -13 %s %s > %s"%(output1, output2, output3)
                                    cmd4 = "rm %s %s"%(output1, output2)

                                    #print(cmd0)
                                    #print(cmd1)
                                    #print(cmd2)
                                    #print(cmd3)
                                    #print(cmd4)
                                    ddisasm_cmd = []
                                    ddisasm_cmd.append(cmd0)
                                    ddisasm_cmd.append(cmd1)
                                    ddisasm_cmd.append(cmd2)
                                    ddisasm_cmd.append(cmd3)
                                    ddisasm_cmd.append(cmd4)
                                    #ret.append(REConf(self.bench, tool_name, self.tool_path, sub_dir, filename, arch, comp, popt, lopt, ddisasm_cmd))
                                    ret.append(ddisasm_cmd)
        return ret

    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(reassem, (self.conf_list))
        else:
            for conf in self.conf_list:
                reassem(conf)


def reassem(conf):
    for cmd in conf:
        print(cmd)
        os.system(cmd)

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    args = parser.parse_args()

    mgr = Ddisasm(args.core)
    #mgr.print_conf()
    mgr.run()
    #mgr.print_compile_cmd()
    #mgr.compile()
