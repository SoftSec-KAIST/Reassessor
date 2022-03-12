from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

#from differ.ereport import ERec

ERec = namedtuple('ERec', ['record', 'gt'])

BuildConf = namedtuple('BuildConf', ['bin', 'gt_asm', 'strip', 'gt_out', 'retro_asm', 'retro_out', 'ddisasm_asm', 'ddisasm_out', 'result'])

def print_conf(conf_list):

    for conf in conf_list:
        print('mkdir -p %s'%(os.path.dirname(conf.gt_out)))
        print('python3 -m normalizer.gt %s %s %s'%(conf.bin, conf.asm, conf.gt_out))
        #print('python3 -m normalizer.retro %s %s %s'%(conf.bin, conf.retro_in, conf.retro_out))
        #print('python3 -m normalize.ddisasm %s %s %s'%(conf.bin, conf.ddisasm_in, conf.ddisasm_out))
        #print('python3 -m differ.diff %s %s %s --retro %s --ddisasm %s'%(conf.bin, conf.gt_out, conf.result, conf.retro_out, conf.ddisasm_out))
        #print('mkdir -p %s'%(os.path.dirname(conf.result)))
        #print('python3 -m differ.diff %s %s %s --retro %s'%(conf.bin, conf.gt_out, conf.result, conf.retro_out))

class RecCounter:
    def __init__(self):
        self.board = list()
        for i in range(9):
            self.board.append({'tp':0, 'fp':0, 'fn':0})

        self.error = 0
        self.tot_gt = 0

    def add(self, pickle_path):
        if not os.path.exists(pickle_path):
            self.error += 1
            return
        print(pickle_path)
        with open(pickle_path , 'rb') as fp:
            rec = pickle.load(fp)


            for stype in range(1, 9):
                self.board[stype]['tp'] += rec.record[stype].tp
                self.board[stype]['fp'] += rec.record[stype].fp.length()
                self.board[stype]['fn'] += rec.record[stype].fn.length()

            self.tot_gt += rec.gt


    def report(self):
        print('        %8s %8s %8s'%('TP', 'FP', 'FN'))
        for stype in range(1, 9):
            print('Type %d: %8d %8d %8d'%(stype, self.board[stype]['tp'] , self.board[stype]['fp'] , self.board[stype]['fn']))

        print('Total : %8d'%(self.tot_gt))



class WorkBin:
    def __init__(self, bench='/data2/benchmark', out='/home/hskim/data/sok/reassem/new_result', retro='/home/hskim/data/sok/reassem/result', ddisasm='/home/hskim/data/sok/reassem/dd_result'):
        self.bench = bench
        self.out = out
        self.retro = retro
        self.ddisasm = ddisasm

    def get_retro(self, sub_dir, filename):
        return '%s/%s/retro_sym/%s.s'%(self.retro, sub_dir, filename)

    def get_ddisasm(self, sub_dir, filename):
        return '%s/%s/ddisasm/%s.s'%(self.retro, sub_dir, filename)

    def get_tuple(self, sub_dir):
        ret = []
        #print('%s/%s/bin/*'%(self.bench, sub_dir))
        for binary in glob.glob('%s/%s/bin/*'%(self.bench, sub_dir)):
            filename = os.path.basename(binary)

            gt_asm = '%s/%s/asm/%s'%(self.bench, sub_dir, filename)
            strip = '%s/stripbin/%s'%(self.bench, filename)
            retro_asm = self.get_retro(sub_dir, filename)
            ddisasm_asm = self.get_ddisasm(sub_dir, filename)

            gt_out = '%s/%s/%s/pickle/gt.dat'%(self.out, sub_dir, filename)
            retro_out = '%s/%s/%s/pickle/retro.dat'%(self.out, sub_dir, filename)
            ddisasm_out = '%s/%s/%s/pickle/ddisasm.dat'%(self.out, sub_dir, filename)

            result = '%s/%s/%s'%(self.out, sub_dir, filename)

            ret.append(BuildConf(binary, gt_asm, strip, gt_out, retro_asm, retro_out, ddisasm_asm, ddisasm_out, result))
            #print(BuildConf(binary, gt_asm, strip, gt_out, retro_asm, retro_out, ddisasm_asm, ddisasm_out))

        return ret


def job(conf, multi=True):
    #create_gt(conf, multi)
    #create_retro(conf, multi)
    #create_ddisasm(conf, multi)
    diff(conf, multi)

def diff(conf, multi=True):
    if not os.path.exists(conf.retro_out):
        return

    if os.path.exists(conf.result+'/error_pickle/retro_sym'):
        return

    os.system('mkdir -p %s'%(os.path.dirname(conf.result)))
    print('python3 -m differ.diff %s %s %s --retro %s'%(conf.bin, conf.gt_out, conf.result, conf.retro_out))
    os.system('python3 -m differ.diff %s %s %s --retro %s'%(conf.bin, conf.gt_out, conf.result, conf.retro_out))


def create_gt(conf, multi):
    create_db('gt',     conf.bin, conf.gt_asm, conf.gt_out, multi)

def create_retro(conf, multi):
    create_db('retro',  conf.bin, conf.retro_asm, conf.retro_out, multi)

def create_db(tool_name, bin_file, assem, output, multi=True):
    if os.path.exists(output):
        return

    if tool_name != 'gt':
        if not os.path.exists(assem):
            return

    if not multi:
        print('python3 -m normalizer.%s %s %s %s'%(tool_name, bin_file, assem, output))

    os.system('mkdir -p %s'%(os.path.dirname(output)))
    os.system('python3 -m normalizer.%s %s %s %s'%(tool_name, bin_file, assem, output))


class Manager:
    def __init__(self, core):
        self.core = core
        if core > 1:
            self.multi = True
        else:
            self.multi = False

        self.conf_list = self.gen_option('/data2/benchmark')

    def gen_option(self, work_dir):
        ret = []
        gen = WorkBin()
        for pack in ['spec_cpu2006']:
            for arch in ['x64']:
                for comp in ['clang', 'gcc']:
                    for popt in ['pie']:
                        #for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                ret.extend(gen.get_tuple(sub_dir))
        return ret


    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(job, (self.conf_list))
        else:
            for conf in self.conf_list:
                job(conf, self.multi)

    def report(self, tool):
        counter = RecCounter()

        for conf in self.conf_list:
            counter.add(conf.result+'/error_pickle/' + tool)

        counter.report()

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    args = parser.parse_args()

    mgr = Manager(args.core)
    mgr.run()

    mgr.report('retro_sym')
