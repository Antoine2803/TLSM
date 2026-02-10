#!/usr/bin/python

from os import mkdir
from os.path import join
from sys import argv

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
        print("Installing policy :", policy)
        f.write(policy)
        f.close()
    except OSError:
        print("Failed to open", SYSFS_ADD, " - Is TLSM loaded ?")
        return -1

def remove_policy(index: int):
    assert(index >= 0)
    try:
        f = open(SYSFS_DEL, "w")
        print("Removing policy at index :", index)
        f.write(str(index))
        f.close()
    except OSError:
        print("Failed to open", SYSFS_ADD, " - Is TLSM loaded ?")
        return -1

def apply_policies():
    print("Loading policies from", policies_path)
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
        print("Failed to open", policies_path)
        exit(1)

def list_policies():
    f = open(SYSFS_LIST, "r")
    for p in f.readlines():
        print(p, end="")
    f.close()

def print_help():
    print("usage: tlsm-py [ apply | list | add \"<policy>\" | del <index> ]")
    print("Policy example : cat open /home/user/secret.txt")
    print("Policy example : python bind 192.168.1.1")

if __name__=="__main__":
    print("tlsm-tools - userland configuration utility for TLSM")
    if len(argv) > 1:
        if argv[1] == "apply":
            apply_policies()
        elif argv[1] == "list":
            list_policies()
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