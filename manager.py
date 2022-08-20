from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

#from differ.ereport import ERec
from differ.statistics import SymStatistics

ERec = namedtuple('ERec', ['record', 'gt'])

BuildConf = namedtuple('BuildConf', ['bin', 'reloc', 'gt_asm', 'strip', 'gt_dir', 'retro_asm', 'retro_dir', 'ddisasm_asm', 'ddisasm_dir', 'ramblr_asm', 'ramblr_dir'])


#black_list = []
#white_list = []

def job(conf, reset=True):
    diff_option = '--error'
    #diff_option = '--disasm'
    #diff_option = ''
    #create_gt(conf, reset)

    '''
    if create_retro(conf, reset):
        diff_retro(conf, diff_option, reset)
    '''
    if create_ddisasm(conf, reset):
        diff_ddisasm(conf, diff_option, reset)
    '''
    if create_ramblr(conf, reset):
        diff_ramblr(conf, diff_option, reset)
    '''
    #diff_retro(conf, diff_option, reset)
    #diff_ddisasm(conf, diff_option, reset)
    #diff_ramblr(conf, diff_option, reset)

class RecCounter:
    def __init__(self, tool):
        self.tool = tool
        self.board = list()
        for i in range(9):
            self.board.append({'tp':0, 'fp':0, 'critical_fp':0, 'fn':0})

        self.no_error = 0

        self.error = 0
        self.success = 0
        self.tot_gt = 0

        self.disasm_tp = 0
        self.disasm_fp = 0
        self.disasm_fn = 0

    def add(self, pickle_path, disasm_path):
        if not os.path.exists(pickle_path):
            #print(pickle_path)
            self.error += 1
            return

        with open(pickle_path , 'rb') as fp:
            self.success += 1
            rec = pickle.load(fp)

            bError = False
            for stype in range(1, 9):
                self.board[stype]['tp'] += rec.record[stype].tp
                self.board[stype]['fp'] += rec.record[stype].fp.length()
                self.board[stype]['critical_fp'] += rec.record[stype].fp.critical_errors()
                self.board[stype]['fn'] += rec.record[stype].fn.length()

                if rec.record[stype].fp.length():
                    bError = True
                if rec.record[stype].fn.length():
                    bError = True

            if not bError:
                self.no_error += 1

            self.tot_gt += rec.gt

        with open(disasm_path) as fp:
            data = fp.readline()
            disasm_tp, disasm_fp, disasm_fn = data.strip().split(',')
            self.disasm_tp += int(disasm_tp)
            self.disasm_fp += int(disasm_fp)
            self.disasm_fn += int(disasm_fn)
            if 1000 < int(disasm_fn) + int(disasm_fp) :
                print('> %-110s %7s %7s'%(disasm_path, disasm_fn, disasm_fp))


    def report(self):
        print('        %8s %8s %8s'%('TP', 'FP', 'FN'))
        for stype in range(1, 9):
            print('Type %d: %8d %8d(%8d) %8d'%(stype, self.board[stype]['tp'] , self.board[stype]['fp'] , self.board[stype]['critical_fp'], self.board[stype]['fn']))

        print('Total : %8d'%(self.tot_gt))



class WorkBin:
    def __init__(self, bench='/data3/1_reassessor/benchmark',
                result_dir='/data3/1_reassessor/result',
                retro  ='/data3/1_reassessor/dataset/retrowrite',
                ddisasm ='/data3/1_reassessor/dataset/ddisasm_debug',
                ramblr  ='/data3/1_reassessor/dataset/ramblr'):

        self.bench = bench

        self.result_dir = result_dir
        self.retro = retro
        self.ddisasm = ddisasm
        self.ramblr = ramblr

    def get_retro(self, sub_dir, filename):
        return '%s/%s/retro_sym/%s.s'%(self.retro, sub_dir, filename)

    def get_ddisasm(self, sub_dir, filename):
        return '%s/%s/ddisasm/%s.s'%(self.ddisasm, sub_dir, filename)

    def get_ramblr(self, sub_dir, filename):
        return '%s/%s/ramblr/%s.s'%(self.ramblr, sub_dir, filename)

    def get_tuple(self, sub_dir, package, arch, pie_opt, rerun_list=None):
        ret = []

        for binary in glob.glob('%s/%s/bin/*'%(self.bench, sub_dir)):
            if rerun_list and binary not in rerun_list:
                continue
            '''
            if os.path.basename(binary) in black_list:
                continue
            if os.path.basename(binary) not in white_list:
                continue
            '''
            ret.append(self.gen_tuple(sub_dir, package, arch, pie_opt, binary))
        return ret

    def gen_tuple(self, sub_dir, package, arch, pie_opt, binary):
        filename = os.path.basename(binary)
        if pie_opt in ['nopie']:
            reloc = '%s/%s/reloc/%s'%(self.bench, sub_dir, filename)
        else:
            reloc = ''

        strip = '%s/stripbin/%s'%(self.bench, filename)

        if package in ['spec_cpu2006', 'cgc']:
            gt_asm = '%s/%s/asm/%s'%(self.bench, sub_dir, filename)
        else:
            gt_asm = '%s/%s/asm'%(self.bench, sub_dir)

        retro_asm = self.get_retro(sub_dir, filename)
        ddisasm_asm = self.get_ddisasm(sub_dir, filename)
        ramblr_asm = self.get_ramblr(sub_dir, filename)

        gt_dir      = '%s/%s/%s/%s/'%(self.result_dir, 'gt',     sub_dir, filename)
        ramblr_dir  = '%s/%s/%s/%s/'%(self.result_dir, 'ramblr', sub_dir, filename)
        retro_dir   = '%s/%s/%s/%s/'%(self.result_dir, 'retro',  sub_dir, filename)
        ddisasm_dir = '%s/%s/%s/%s/'%(self.result_dir, 'ddisasm',sub_dir, filename)

        if pie_opt in ['pie']:
            ramblr_asm = ''
            ramblr_dir = ''
        if pie_opt in ['nopie'] or arch in ['x86']:
            retro_asm = ''
            retro_dir = ''

        return BuildConf(binary, reloc, gt_asm, strip, gt_dir, retro_asm, retro_dir, ddisasm_asm, ddisasm_dir, ramblr_asm, ramblr_dir)


def diff_retro(conf, option, reset):
    if not conf.retro_asm or not os.path.exists(conf.retro_asm):
        return
    if conf.retro_dir:
        diff('retro', conf.bin, conf.gt_dir, conf.retro_dir, option, reset)

def diff_ddisasm(conf, option, reset):
    if not conf.ddisasm_asm or not os.path.exists(conf.ddisasm_asm):
        return
    if conf.ddisasm_dir:
        diff('ddisasm', conf.bin, conf.gt_dir, conf.ddisasm_dir, option, reset)

def diff_ramblr(conf, option, reset):
    if not conf.ramblr_asm or not os.path.exists(conf.ramblr_asm):
        return
    if conf.ramblr_dir:
        diff('ramblr', conf.bin, conf.gt_dir, conf.ramblr_dir, option, reset)


def diff(tool_name, binfile, gt_dir, tool_dir, option, reset):
    gt_out      = gt_dir + 'norm/pickle.dat'
    tool_out    = tool_dir + 'norm/pickle.dat'
    result_dir  = tool_dir + 'diff'

    if os.path.getsize(tool_out) == 0:
        return

    pickle_path = result_dir + '/error_pickle.dat'

    # create new pickle
    if not reset and os.path.exists(pickle_path):
        return

    os.system('mkdir -p %s'%(result_dir))
    os.system('python3 -m differ.diff %s %s %s --%s %s %s'%(binfile, gt_out, result_dir, tool_name, tool_out, option))


def make_symbol_statistics(conf):
    pickle_file = conf.gt_dir + 'norm/pickle.dat'
    output = conf.gt_dir + 'norm/symdist.txt'
    stat = SymStatistics(pickle_file)
    stat.save(output)


def create_gt(conf, reset):
    if create_db('gt',     conf.bin, conf.gt_asm, conf.gt_dir, reset, conf.reloc):
        make_symbol_statistics(conf)
        return True

    return False

def create_retro(conf, reset):
    if conf.retro_asm:
        return create_db('retro',  conf.bin, conf.retro_asm, conf.retro_dir, reset)
    return False

def create_ddisasm(conf, reset):
    if conf.ddisasm_asm:
        return create_db('ddisasm',  conf.bin, conf.ddisasm_asm, conf.ddisasm_dir, reset)
    return False

def create_ramblr(conf, reset):
    if conf.ramblr_asm:
        return create_db('ramblr',  conf.bin, conf.ramblr_asm, conf.ramblr_dir, reset)
    return False

def create_db(tool_name, bin_file, assem, output_dir, reset=False, reloc=''):
    output  = output_dir + 'norm/pickle.dat'

    if not reset and os.path.exists(output):
        return False
    option = ''
    if tool_name != 'gt':
        #print(assem)
        if not os.path.exists(assem):
            return False
        if os.path.getsize(assem) == 0:
            return False
    elif tool_name == 'gt' and reloc:
        option = '--reloc %s'%(reloc)

    print('python3 -m normalizer.%s %s %s %s %s'%(tool_name, bin_file, assem, output, option))

    os.system('mkdir -p %s'%(os.path.dirname(output)))
    os.system('python3 -m normalizer.%s %s %s %s %s'%(tool_name, bin_file, assem, output, option))
    return True

class Manager:
    def __init__(self, core, rerun):
        self.core = core
        if core > 1:
            self.multi = True
        else:
            self.multi = False

        self.rerun_list = []
        if rerun:
            with open(rerun) as f:
                self.rerun_list = [line for line in f.read().split()]

        self.conf_list = self.gen_option('/data2/benchmark')

    def gen_option(self, work_dir):
        ret = []
        gen = WorkBin()
        for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
        #for pack in ['coreutils-8.30']:
        #for pack in ['binutils-2.31.1', 'spec_cpu2006']:
            for arch in ['x86', 'x64']:
                for comp in ['clang', 'gcc']:
                    for popt in ['pie', 'nopie']:
                        for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                ret.extend(gen.get_tuple(sub_dir, pack, arch, popt, rerun_list=self.rerun_list))
        return ret

    def single_run(self, target):
        path = os.path.dirname(target)
        filename = os.path.basename(target)

        sub_dir = '/'.join(path.split('/')[-6:-1])
        (package, arch, comp, pie_opt, lopt) = sub_dir.split('/')
        assert package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006', 'cgc'], 'invalid package'

        gen = WorkBin()
        conf = gen.gen_tuple(sub_dir, package, arch, pie_opt, target)
        job(conf, reset=True)

    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(job, (self.conf_list))
        else:
            for conf in self.conf_list:
                job(conf)

    def merge(self, tool, white_list):
        counter = RecCounter(tool)
        if white_list:
            f = open(white_list)
            my_list = [line for line in f.read().split()]


        for conf in self.conf_list:

            if white_list:
                if conf.ddisasm_asm not in my_list:
                    continue

            if tool == 'ramblr':
                if not conf.ramblr_asm:
                    continue
                out_dir = conf.ramblr_dir
            elif tool == 'retro_sym':
                if not conf.retro_asm:
                    continue
                out_dir = conf.retro_dir
            elif tool == 'ddisasm':
                if not conf.ddisasm_asm:
                    continue
                out_dir = conf.ddisasm_dir

            pickle = out_dir+'diff/error_pickle.dat'
            disasm = out_dir+'diff/disasm_diff.txt'
            counter.add(pickle, disasm)

        #counter.report()
        return counter

    def report(self, white_list=None):
        #---------------------------------------------
        retro = self.merge('retro_sym', white_list)
        ddisasm = self.merge('ddisasm', white_list)
        ramblr = self.merge('ramblr', white_list)

        print('                   %12s  %12s  %12s'%('Ramblr', 'RetroWrite', 'Ddisasm'))
        print('-' * 60 )
        print('# of Bins          %12d  %12d  %12d'%(ramblr.success, retro.success, ddisasm.success))
        print('# of Bins (FAIL)   %12d  %12d  %12d'%(ramblr.error, retro.error, ddisasm.error))
        print('# of Bins (TOTAL)  %12d  %12d  %12d'%(ramblr.success+ramblr.error, retro.success+retro.error, ddisasm.success+ddisasm.error))
        print('-' * 60 )

        for stype in range(1, 9):
            print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.board[stype]['tp'], retro.board[stype]['tp'], ddisasm.board[stype]['tp']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['fp'], retro.board[stype]['fp'], ddisasm.board[stype]['fp']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['critical_fp'], retro.board[stype]['critical_fp'], ddisasm.board[stype]['critical_fp']))
            print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.board[stype]['fn'], retro.board[stype]['fn'], ddisasm.board[stype]['fn']))
            print('-' * 60 )

        print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.disasm_tp, retro.disasm_tp, ddisasm.disasm_tp))
        print('%7s  # of FPs  %12d  %12d  %12d'%('Disasm',ramblr.disasm_fp, retro.disasm_fp, ddisasm.disasm_fp))
        print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.disasm_fn, retro.disasm_fn, ddisasm.disasm_fn))
        print('-' * 60 )

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    parser.add_argument('--target', type=str)
    parser.add_argument('--list', type=str)
    parser.add_argument('--rerun', type=str)
    args = parser.parse_args()

    mgr = Manager(args.core, args.rerun)

    if args.target:
        mgr.single_run(args.target)
    elif args.list:
        mgr.report(args.list)
    else:
        mgr.run()
        mgr.report()

