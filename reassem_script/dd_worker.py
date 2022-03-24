from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

#from differ.ereport import ERec


DdisasmConf = namedtuple('DdisasmConf', ['bench', 'ddisasm', 'sub_dir', 'filename'])

def job(conf, multi=True):
    outpath = '%s/%s/ddisasm/%s.s'%(conf.ddisasm, conf.sub_dir, conf.filename)
    if os.path.exists(outpath):
        return

    if not multi:
        print('sudo docker run --rm -v %s/:/input  -v %s/:/output grammatech/ddisasm:1.5.2 sh -c "ddisasm /input/%s/stripbin/%s --asm /output/%s/ddisasm/%s.s --debug"'%(conf.bench, conf.ddisasm, conf.sub_dir, conf.filename, conf.sub_dir, conf.filename))

    os.system('mkdir -p %s/%s/ddisasm/'%(conf.ddisasm, conf.sub_dir))
    os.system('sudo docker run --rm -v %s/:/input  -v %s/:/output grammatech/ddisasm:1.5.2 sh -c "ddisasm /input/%s/stripbin/%s --asm /output/%s/ddisasm/%s.s --debug"'%(conf.bench, conf.ddisasm, conf.sub_dir, conf.filename, conf.sub_dir, conf.filename))

class Manager:
    def __init__(self, core, bench='/data3/1_reassessor/benchmark', ddisasm='/data3/1_reassessor/debug_dd'):
        self.core = core
        if core > 1:
            self.multi = True
        else:
            self.multi = False
        self.bench = bench
        self.ddisasm = ddisasm
        self.conf_list = self.gen_option(self.bench)

    def gen_option(self, work_dir):
        ret = []
        for pack in ['spec_cpu2006']:
            for arch in ['x64']:
                for comp in ['clang', 'gcc']:
                    for popt in ['pie']:
                        #for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                for binary in glob.glob('%s/%s/bin/*'%(work_dir, sub_dir)):
                                    filename = os.path.basename(binary)

                                    ret.append(DdisasmConf(self.bench, self.ddisasm, sub_dir, filename))
        return ret


    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(job, (self.conf_list))
        else:
            for conf in self.conf_list:
                job(conf, self.multi)

    def get_ddisasm(self, sub_dir, filename):
        return '%s/%s/ddisasm/%s.s'%(self.ddisasm, sub_dir, filename)

    def print_conf(self):
        for conf in self.conf_list:
            print('mkdir -p %s/%s/ddisasm/'%(self.ddisasm, conf.sub_dir))
            print('sudo docker run --rm -v %s/:/input  -v %s/:/output grammatech/ddisasm:1.5.2 sh -c "ddisasm /input/%s/stripbin/%s --asm /output/%s/ddisasm/%s.s --debug"'%(conf.bench, conf.ddisasm, conf.sub_dir, conf.filename, conf.sub_dir, conf.filename))



import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    args = parser.parse_args()

    mgr = Manager(args.core)
    #mgr.print_conf()
    mgr.run()

    #mgr.report('retro_sym')
