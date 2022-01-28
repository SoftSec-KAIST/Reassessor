import sys, os
from utils import *
import json

objrel_in_code_num = 0
objrel_in_data_num = 0

objrel_code = 0
objrel_data = 0

objrel_code_cases = []

composite_in_code_num = 0
composite_in_data_num = 0

composite_code = 0
composite_data = 0

composite_type2 = 0
composite_type4 = 0
composite_type6 = 0

def main(bench_dir, stat_dir):
    global objrel_in_code_num, objrel_in_data_num, objrel_code, objrel_data, composite_in_code_num, composite_in_data_num, composite_code, composite_data, composite_type2, composite_type4, composite_type6
    for package, arch, compiler, pie, opt in gen_options():
        print(package, arch, compiler, pie, opt)
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            stat_path = os.path.join(stat_base, name)
            if not os.path.exists(stat_path):
                continue
            with open(stat_path) as f:
                res = json.loads(f.read())

            objrel_in_code_num += len(res['ObjRel_Code'])
            objrel_in_data_num += len(res['ObjRel_Data'])

            for addr in res['ObjRel_Code']:
                if res['ObjRel_Code'][addr][0]:
                    objrel_code += 1
                else:
                    objrel_data += 1
            for addr in res['ObjRel_Data']:
                if res['ObjRel_Data'][addr][0]:
                    objrel_code += 1
                else:
                    objrel_data += 1

            composite_in_code_num += len(res['Composite_Code'])
            composite_in_data_num += len(res['Composite_Data'])

            for addr in res['Composite_Code']:
                if res['Composite_Code'][addr][0]:
                    composite_code += 1
                    bin_path = os.path.join(bin_dir, name)
                    objrel_code_cases.append((bin_path, addr, res['Composite_Code'][addr]))
                    result = res['Composite_Code'][addr]
                    if result[3] == 'ABSOLUTE':
                        composite_type2 += 1
                    elif result[3] == 'PCREL':
                        composite_type4 += 1
                    elif result[3] == 'GOTOFF':
                        composite_type6 += 1
                else:
                    composite_data += 1
                    result = res['Composite_Code'][addr]
                    if result[3] == 'ABSOLUTE':
                        composite_type2 += 1
                    elif result[3] == 'PCREL':
                        composite_type4 += 1
                    elif result[3] == 'GOTOFF':
                        composite_type6 += 1

            for addr in res['Composite_Data']:
                if res['Composite_Data'][addr][0]:
                    composite_code += 1
                    bin_path = os.path.join(bin_dir, name)
                    objrel_code_cases.append((bin_path, addr, res['Composite_Data'][addr]))
                    result = res['Composite_Data'][addr]
                    if result[3] == 'ABSOLUTE':
                        composite_type2 += 1
                    elif result[3] == 'PCREL':
                        composite_type4 += 1
                    elif result[3] == 'GOTOFF':
                        composite_type6 += 1
                else:
                    composite_data += 1
                    result = res['Composite_Data'][addr]
                    if result[3] == 'ABSOLUTE':
                        composite_type2 += 1
                    elif result[3] == 'PCREL':
                        composite_type4 += 1
                    elif result[3] == 'GOTOFF':
                        composite_type6 += 1

    print(objrel_in_code_num)
    print(objrel_in_data_num)
    print(objrel_code)
    print(objrel_data)
    print(composite_in_code_num)
    print(composite_in_data_num)
    print(composite_code)
    print(composite_data)

    print(composite_type2, composite_type4, composite_type6)

    with open('/home/soomink/list', 'w') as f:
        for binpath, addr, result in objrel_code_cases:
            _, path, line = result
            f.write('%s, %s, %s, %s\n' % (binpath, addr, path, line))

if __name__ == '__main__':
    #bench_dir = sys.argv[1]
    bench_dir = '/data2/benchmark'
    #stat_dir = sys.argv[2]
    stat_dir = '/home/soomink/triage3'
    main(bench_dir, stat_dir)
