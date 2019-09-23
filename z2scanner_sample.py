import argparse
from datetime import datetime
from glob import glob
import hashlib
import os
import sys


parser = argparse.ArgumentParser()
parser.add_argument("path", help="A target file or directory. Beware that you have to use the -d option when you scan a directory.")
parser.add_argument("-d", "--dir", action="store_true", help="Use directory scan mode")
parser.add_argument("-v", "--verbose", action="store_true")
args = parser.parse_args()


version = "0.0.1"
md5sum_malicious = "26cd7ef06f358bdb5bf20f109f41aead"


def output_result(kwargs):
    print("target_path:{path}\tscanner_version:{version}\t".format(**kwargs), end="")
    print("scan_date:{datetime}\tis_malicious:{is_malicious}\t".format(**kwargs), end="")
    print("reason_method:{reason_method}".format(**kwargs))


def get_md5sum(path):
    md5 = hashlib.md5()

    with open(path, "rb") as target:
        for chunk in iter(lambda: target.read(2048 * md5.block_size), b''):
            md5.update(chunk)

    md5sum = md5.hexdigest()

    if args.verbose:
        print("CALCULATING MD5SUM OF {}...".format(path))
        print(md5sum)

    return md5sum


def scan_file(path):
    if not path:
        return 0

    today = datetime.today()
    dt = today.strftime("%Y-%m-%d_%H-%M-%S")
    # -- YOUR DETECTION LOGIC IN HERE --
    md5sum = get_md5sum(path)

    is_malicious = True if md5sum == md5sum_malicious else False
    reason_method = "Embedded-Signatures" if is_malicious else "" 
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
