from manager import Manager, REConf
import os
import glob

def ddisasm_cmd(conf):
    cmd_list = []

    bfile = '%s/stripbin/%s'%(conf.sub_dir, conf.filename)
    rfile = '%s/%s/%s.s'%(conf.sub_dir, conf.tool_name, conf.filename)

    cmd1 = 'mkdir -p %s/%s'%(conf.tool_path, os.path.dirname(rfile))
    cmd_list.append(cmd1)
    #cmd2 = 'sudo docker run --rm -v %s/:/input  -v %s/:/output grammatech/ddisasm:1.5.3 sh -c "ddisasm /input/%s --asm /output/%s --debug"'%(conf.bench, conf.tool_path, bfile, rfile)
    cmd2 = 'sudo docker run --rm -v %s/:/input  -v %s/:/output grammatech/ddisasm:1.5.3 sh -c "ddisasm /input/%s --asm /output/%s"'%(conf.bench, conf.tool_path, bfile, rfile)
    cmd_list.append(cmd2)
    return cmd_list


class Ddisasm(Manager):
    #def __init__(self, core, bench='/data3/1_reassessor/benchmark', tool_path='/data3/1_reassessor/debug_dd2', tool_name='ddisasm'):
    def __init__(self, core, bench='/data3/1_reassessor/benchmark', tool_path='/data3/1_reassessor/new_ddisasm2', tool_name='ddisasm'):
        self.overwrite = False
        super().__init__(core, bench, tool_path, tool_name)

    def gen_option(self, work_dir, tool_name):
        ret = []
        #for pack in ['coreutils-8.30', 'binutils-2.31.1']:
        #for pack in ['spec_cpu2006']:
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

                                    '''
                                    if not self.overwrite:
                                        output = '%s/%s/%s/%s.s'%(self.tool_path, sub_dir, tool_name, filename)
                                        if os.path.isfile(output):
                                            continue
                                        #print(output)
                                    '''

                                    ret.append(REConf(self.bench, tool_name, self.tool_path, sub_dir, filename, arch, comp, popt, lopt, ddisasm_cmd))
        return ret


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    args = parser.parse_args()

    mgr = Ddisasm(args.core)
    #mgr.print_conf()
    #mgr.run()
    #mgr.print_compile_cmd()
    mgr.compile()
