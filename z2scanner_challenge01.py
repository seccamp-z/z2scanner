import argparse
from datetime import datetime
from glob import glob
import hashlib
import os
import sys
import z2kit3.utils

parser = argparse.ArgumentParser()
parser.add_argument("path", help="A target file or directory. Beware that you have to use the -d option when you scan a directory.")
parser.add_argument("-d", "--dir", action="store_true", help="Use directory scan mode")
parser.add_argument("-v", "--verbose", action="store_true")
args = parser.parse_args()


version = "0.0.1"


def output_result(kwargs):
    print("target_path:{path}\tscanner_version:{version}\t".format(**kwargs), end="")
    print("scan_date:{datetime}\tis_malicious:{is_malicious}\t".format(**kwargs), end="")
    print("reason_method:{reason_method}".format(**kwargs))


def find_string(path):
    with open(path, "rb") as f:
      strings = z2kit3.utils.get_strings(f.read())
    print(strings.keys())
    return list(strings.keys())

def scan_file(path):
    YOUR_PATTERNS = ['Mini']
    is_malicious = False
    reason_method = ""
    if not path:
        return 0
    today = datetime.today()
    dt = today.strftime("%Y-%m-%d_%H-%M-%S")
    
    # -- YOUR DETECTION LOGIC IN HERE -- 
    #if YOUR_PATTERNS in find_string(path):
    #  is_malicious = True
    #  reason_method = "ByteStream-XXXX-Signatures"
    kwargs = {
        "path": path,
        "version": version,
        "datetime": dt,
        "is_malicious": str(is_malicious),
        "reason_method": reason_method,
    }
    #--------
    output_result(kwargs)


def scan_dir(path):
    fd_rpath_list = glob(os.path.join(path, "**"), recursive=True)
    fl_rpath_list = [f for f in fd_rpath_list if os.path.isfile(f)]


    for f in fl_rpath_list:
        scan_file(f)


def main():
    if args.dir:
        if os.path.isdir(args.path):
            scan_dir(args.path)
        else:
            sys.exit("ERROR: {} is not a directory.".format(args.path))
    else:
        if os.path.isfile(args.path):
            scan_file(args.path)
        else:
            sys.exit("ERROR: {} is not a file".format(args.path))


if __name__ == "__main__":
    main()
