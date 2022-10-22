import os
import pickle
from reassessor.normalizer import retro, ramblr, ddisasm, gt
from .statistics import Statistics
from .ereport import Report


def diff(bin_path, pickle_gt_path, pickle_tool_dict, save_dir, error_check=True, disasm_check=True, reset=False):


    # Load GT
    if not os.path.exists(pickle_gt_path):
        print('No gt ' + pickle_gt_path)
        return

    pickle_gt_f = open(pickle_gt_path, 'rb')
    prog_c = pickle.load(pickle_gt_f)
    stat = Statistics(prog_c)

    for tool, pickle_tool_path in pickle_tool_dict.items():
        pickle_tool_f = open(pickle_tool_path, 'rb')
        prog_r = pickle.load(pickle_tool_f)

        if error_check:
            sym_diff_file_path = '%s/%s/sym_diff.txt'%(save_dir,tool)
            error_json_file_path = '%s/%s/sym_errors.json'%(save_dir, tool)
            error_pickle_file_path = '%s/%s/sym_errors.dat'%(save_dir, tool)

            if os.path.exists(sym_diff_file_path) and not reset:
                pass
            else:
                report = Report(bin_path, prog_c)
                report.compare(prog_r)
                report.save_file(sym_diff_file_path)
                report.save_file(error_json_file_path, option='json')
                report.save_pickle(error_pickle_file_path)

        if disasm_check:
            disasm_file_path = '%s/%s/disasm_diff.txt'%(save_dir, tool)
            if os.path.exists(disasm_file_path) and not reset:
                pass
            else:
                stat.count_disasm(prog_r, disasm_file_path)

        pickle_tool_f.close()

    pickle_gt_f.close()


import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='differ')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('pickle_gt_path', type=str)
    parser.add_argument('save_dir', type=str)
    parser.add_argument('--ddisasm', type=str)
    parser.add_argument('--ramblr', type=str)
    parser.add_argument('--retro', type=str)
    parser.add_argument('--error', action='store_true')
    parser.add_argument('--disasm', action='store_true')
    args = parser.parse_args()

    pickle_tool_dict = dict()
    if args.ddisasm:
        pickle_tool_dict['ddisasm'] = args.ddisasm
    if args.ramblr:
        pickle_tool_dict['ramblr'] = args.ramblr
    if args.retro:
        pickle_tool_dict['retrowrite'] = args.retro

    if pickle_tool_dict:
        if args.error and not args.disasm:
            diff(args.bin_path, args.pickle_gt_path, pickle_tool_dict, args.save_dir, error_check=True, disasm_check=False, reset=True )
        elif not args.error and args.disasm:
            diff(args.bin_path, args.pickle_gt_path, pickle_tool_dict, args.save_dir, error_check=False, disasm_check=True, reset=True )
        else:
            diff(args.bin_path, args.pickle_gt_path, pickle_tool_dict, args.save_dir, reset=True)


