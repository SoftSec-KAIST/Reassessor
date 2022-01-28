import glob
import json
import sys

def main(func_dir, out_file):

    a = glob.glob(func_dir+"/*/*/*/*/*/result.json")
    result = {}

    for f in a:
        t = json.load(open(f, 'r'))
        result.update(t)

    with open(out_file,"w") as ff:
        json.dump(result, ff)

if __name__ == '__main__':
    func_dir = sys.argv[1]
    out_file = sys.argv[2]
    main(func_dir, out_file)
