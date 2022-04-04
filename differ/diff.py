import os
import pickle
import normalizer.retro
import normalizer.ramblr
import normalizer.ddisasm
import normalizer.gt
from differ.statistics import Statistics
from differ.ereport import Report


def diff(bin_path, pickle_gt_path, pickle_tool_list, save_dir, error_check=True, disasm_check=True):

    out_dir = os.path.join(save_dir, 'error_ascii')
    pr_dir = os.path.join(save_dir, 'error_score')
    json_dir = os.path.join(save_dir, 'error_json')
    pickle_dir = os.path.join(save_dir, 'error_pickle')

    disasm_dir = os.path.join(save_dir, 'disasm_diff')
    type_dir = os.path.join(save_dir, 'sym_dist')
    #err_dir = os.path.join(save_dir, 'error')


    # Load GT
    if not os.path.exists(pickle_gt_path):
        print('No gt ' + pickle_gt_path)
        return

    pickle_gt_f = open(pickle_gt_path, 'rb')
    prog_c = pickle.load(pickle_gt_f)
    stat = Statistics(prog_c)

    gt_type_file_path = '%s/%s'%(type_dir, 'gt')
    stat.count_symbols(prog_c, gt_type_file_path)

    for tool, pickle_tool_path in pickle_tool_list.items():
        pickle_tool_f = open(pickle_tool_path, 'rb')
        prog_r = pickle.load(pickle_tool_f)

        if error_check:
            out_file_path = '%s/%s'%(out_dir, tool)
            pr_file_path = '%s/%s'%(pr_dir, tool)
            json_file_path = '%s/%s'%(json_dir, tool)
            pickle_file_path = '%s/%s'%(pickle_dir, tool)

            report = Report(prog_c)
            report.compare(prog_r)
            report.save_file(out_file_path, option='ascii')
            report.save_pickle(pickle_file_path)

        if disasm_check:
            disasm_file_path = '%s/%s'%(disasm_dir, tool)
            type_file_path = '%s/%s'%(type_dir, tool)

            stat.count_symbols(prog_r, type_file_path)
            stat.count_disasm(prog_r, disasm_file_path)


        pickle_tool_f.close()

        #err_file.close()

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


