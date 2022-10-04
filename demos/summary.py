from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

black_list = []
white_list = []


class RecCounter:
    def __init__(self, tool):
        self.tool = tool
        self.board = list()
        for i in range(9):
            self.board.append({'tp':0, 'fp':0, 'fatal_fp':0, 'non-fatal_fp':0, 'fn':0})

        self.no_error = 0

        self.error = 0
        self.success = 0
        self.tot_gt = 0

        self.disasm_tp = 0
        self.disasm_fp = 0
        self.disasm_fn = 0

    def add(self, pickle_path, disasm_path):
        if not os.path.exists(pickle_path):
            self.error += 1
            return

        print(pickle_path)
        with open(pickle_path , 'rb') as fp:
            self.success += 1
            rec = pickle.load(fp)

            bError = False
            for stype in range(1, 9):
                self.board[stype]['tp'] += rec.record[stype].tp
                self.board[stype]['fp'] += rec.record[stype].fp.length()
                self.board[stype]['fatal_fp'] += rec.record[stype].fp.critical_errors()
                self.board[stype]['non-fatal_fp'] += rec.record[stype].fp.length() - rec.record[stype].fp.critical_errors()
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


    def report(self):
        print('        %8s %8s %8s'%('TP', 'FP', 'FN'))
        for stype in range(1, 9):
            print('Type %d: %8d %8d(%8d) %8d'%(stype, self.board[stype]['tp'] , self.board[stype]['fp'] , self.board[stype]['fatal_fp'], self.board[stype]['fn']))

        print('Total : %8d'%(self.tot_gt))


BuildConf = namedtuple('BuildConf', ['output_dir', 'arch', 'pie'])

class Manager:
    def __init__(self, package, input_root='./dataset', output_root='./output'):
        self.conf_list = self.gen_option(input_root, output_root, package)

    def gen_option(self, input_root, output_root, package):
        ret = []
        for arch in ['x86', 'x64']:
            for comp in ['clang', 'gcc']:
                for popt in ['pie', 'nopie']:
                    for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        for lopt in ['bfd', 'gold']:
                            sub_dir = '%s/%s/%s/%s/%s-%s'%(package, arch, comp, popt, opt, lopt)

                            for target in glob.glob('%s/%s/reloc/*'%(input_root, sub_dir)):

                                filename = os.path.basename(target)

                                output_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                                ret.append(BuildConf(output_dir, arch, popt))
        return ret


    def merge(self, tool, white_list):
        counter = RecCounter(tool)
        if white_list:
            f = open(white_list)
            my_list = [line for line in f.read().split()]


        for conf in self.conf_list:

            if white_list:
                if conf.ddisasm_asm not in my_list:
                    continue

            if tool == 'retrowrite':
                if conf.pie != 'pie' or conf.arch != 'x64':
                    continue
            elif tool == 'ramblr':
                if conf.pie != 'nopie':
                    continue
            elif tool != 'ddisasm':
                continue

            pickle = conf.output_dir+'/errors/%s/sym_errors.dat'%(tool)
            disasm = conf.output_dir+'/errors/%s/disasm_diff.txt'%(tool)

            counter.add(pickle, disasm)

        return counter

    def report_sum(self, white_list=None):
        #---------------------------------------------
        retro = self.merge('retrowrite', white_list)
        ddisasm = self.merge('ddisasm', white_list)
        ramblr = self.merge('ramblr', white_list)
        self.report(ramblr, retro, ddisasm)

    def report(self, ramblr, retro, ddisasm):
        print('-' * 60 )
        print('                   %12s  %12s  %12s'%('Ramblr', 'RetroWrite', 'Ddisasm'))
        print('%7s  # of Succ %12d  %12d  %12d'%('',ramblr.no_error, retro.no_error, ddisasm.no_error))
        print('-' * 60 )
        print('# of Bins          %12d  %12d  %12d'%(ramblr.success, retro.success, ddisasm.success))
        print('# of Bins (FAIL)   %12d  %12d  %12d'%(ramblr.error, retro.error, ddisasm.error))
        print('# of Bins (TOTAL)  %12d  %12d  %12d'%(ramblr.success+ramblr.error, retro.success+retro.error, ddisasm.success+ddisasm.error))
        print('-' * 60 )

        for stype in range(1, 9):
            print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.board[stype]['tp'], retro.board[stype]['tp'], ddisasm.board[stype]['tp']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['fp'], retro.board[stype]['fp'], ddisasm.board[stype]['fp']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['fatal_fp'], retro.board[stype]['fatal_fp'], ddisasm.board[stype]['fatal_fp']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['non-fatal_fp'], retro.board[stype]['non-fatal_fp'], ddisasm.board[stype]['non-fatal_fp']))
            print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.board[stype]['fn'], retro.board[stype]['fn'], ddisasm.board[stype]['fn']))
            print('-' * 60 )

        print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.disasm_tp, retro.disasm_tp, ddisasm.disasm_tp))
        print('%7s  # of FPs  %12d  %12d  %12d'%('Disasm',ramblr.disasm_fp, retro.disasm_fp, ddisasm.disasm_fp))
        print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.disasm_fn, retro.disasm_fn, ddisasm.disasm_fn))
        print('-' * 60 )




import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--package', type=str, help='Package')
    args = parser.parse_args()

    if args.package:
        mgr = Manager(args.package, input_root='./dataset', output_root='./output')
    else:
        for package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            mgr = Manager(package, input_root='./dataset', output_root='./output')

    mgr.report_sum()

