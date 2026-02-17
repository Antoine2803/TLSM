#!/usr/bin/python

from os import mkdir
from os.path import join
from sys import argv

class term_colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

TAG_INFO = term_colors.BOLD + term_colors.OKBLUE + "[INFO]" + term_colors.ENDC
TAG_WARN = term_colors.BOLD + term_colors.WARNING + "[WARNING]" + term_colors.ENDC
TAG_ERR = term_colors.BOLD + term_colors.FAIL + "[ERROR]" + term_colors.ENDC
TAG_POL = term_colors.BOLD + term_colors.OKGREEN + "[POL]" + term_colors.ENDC
TAG_POLD = term_colors.BOLD + term_colors.WARNING + "[POL]" + term_colors.ENDC

MAIN_FOLDER="/etc/tlsm/"
POLICIES_DB="policies.conf"

policies_path = join(MAIN_FOLDER, POLICIES_DB)

SYSFS_ROOT = "/sys/kernel/security/tlsm/"
SYSFS_ADD = join(SYSFS_ROOT, "add_policy")
SYSFS_DEL = join(SYSFS_ROOT, "del_policy")
SYSFS_LIST = join(SYSFS_ROOT, "list_policies")

def create_folders():
    mkdir(MAIN_FOLDER)

def add_policy(policy: str):
    try:
        f = open(SYSFS_ADD, "w")
        print(f"{TAG_POL} Installing policy :", policy)
        f.write(policy)
        f.close()
    except OSError:
        print(f"{TAG_ERR} Failed to open", SYSFS_ADD, " - Is TLSM loaded ?")
        return -1

def remove_policy(index: int):
    assert(index >= 0)
    try:
        f = open(SYSFS_DEL, "w")
        print(f"{TAG_POLD}Removing policy at index :", index)
        f.write(str(index))
        f.close()
    except OSError:
        print(f"{TAG_ERR} Failed to open", SYSFS_ADD, " - Is TLSM loaded ?")
        return -1
    
def flush_policies():
    print(f"{TAG_INFO} Removing all policies")
    lines = 0
    with open(SYSFS_LIST, "r") as f:
        lines = sum(1 for _ in f)
    print(f"{TAG_INFO} Detected", lines, "lines to delete")
    f = open(SYSFS_DEL, "w")
    for _ in range(lines):
        f.write('0')
        f.flush()
    f.close()

def apply_policies():
    print(f"{TAG_INFO} Loading policies from", policies_path)
    try:
        policies = open(policies_path, "r")
        program = None
        for i in policies.readlines():
            try:
                i = i.rstrip(" \n")
                lt = i[0]
                lh = i[1:]
                if lt == "@":
                    program = lh
                elif lt == "=":
                    add_policy(program + " " + lh)
            except IndexError:
                pass
        policies.close()
    except OSError:
        print(f"{TAG_ERR} Failed to open", policies_path)
        exit(1)

def list_policies():
    f = open(SYSFS_LIST, "r")
    for p in f.readlines():
        print(p, end="")
    f.close()

def print_help():
    print(f"{term_colors.BOLD} tlsm-tools {term_colors.ENDC} - userland configuration utility for TLSM")
    print("usage: tlsm-py [ apply | list | add \"<policy>\" | del <index> | flush ]")
    print("Policy example : cat open /home/user/secret.txt")
    print("Policy example : python ask bind 192.168.1.1")

if __name__=="__main__":
    if len(argv) > 1:
        if argv[1] == "apply" or argv[1] == "a":
            apply_policies()
        elif argv[1] == "list":
            list_policies()
        elif argv[1] == "flush":
            flush_policies()
        elif argv[1] == "add":
            if len(argv) == 3:
                pol = argv[2]
                add_policy(pol)
            else:
                print_help()
        elif argv[1] == "del":
            if len(argv) == 3:
                index = int(argv[2])
                remove_policy(index)
            else:
                print_help()
        else:
            print_help()
    else:
        print_help()
    
    exit(0)