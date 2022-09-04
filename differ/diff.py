import os
import pickle
import normalizer.retro
import normalizer.ramblr
import normalizer.ddisasm
import normalizer.gt
from differ.statistics import Statistics
from differ.ereport import Report


def diff(bin_path, pickle_gt_path, pickle_tool_list, save_dir, error_check=True, disasm_check=True):


    # Load GT
    if not os.path.exists(pickle_gt_path):
        print('No gt ' + pickle_gt_path)
        return

    pickle_gt_f = open(pickle_gt_path, 'rb')
    prog_c = pickle.load(pickle_gt_f)
    stat = Statistics(prog_c)

    for tool, pickle_tool_path in pickle_tool_list.items():
        pickle_tool_f = open(pickle_tool_path, 'rb')
        prog_r = pickle.load(pickle_tool_f)

        if error_check:
            out_file_path = save_dir + '/error_ascii.txt'
            json_file_path = save_dir + '/errors.json'
            pickle_file_path = save_dir + '/error_pickle.dat'

            report = Report(bin_path, prog_c)
            report.compare(prog_r)
            report.save_file(out_file_path)
            #report.save_file(json_file_path, option='json')
            report.save_pickle(pickle_file_path)

        if disasm_check:
            disasm_file_path = save_dir + '/disasm_diff.txt'
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

    pickle_tool_list = dict()
    if args.ddisasm:
        pickle_tool_list['ddisasm'] = args.ddisasm
    if args.ramblr:
        pickle_tool_list['ramblr'] = args.ramblr
    if args.retro:
        pickle_tool_list['retro_sym'] = args.retro

    if pickle_tool_list:
        if args.error and not args.disasm:
            diff(args.bin_path, args.pickle_gt_path, pickle_tool_list, args.save_dir, error_check=True, disasm_check=False )
        elif not args.error and args.disasm:
            diff(args.bin_path, args.pickle_gt_path, pickle_tool_list, args.save_dir, error_check=False, disasm_check=True )
        else:
            diff(args.bin_path, args.pickle_gt_path, pickle_tool_list, args.save_dir)


