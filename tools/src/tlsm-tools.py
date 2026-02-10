#!/usr/bin/python

from os import mkdir
from os.path import join
from sys import argv

MAIN_FOLDER="/etc/tlsm/"
POLICIES_DB="policies.conf"

policies_path = join(MAIN_FOLDER, POLICIES_DB)

SYSFS_ROOT = "/sys/kernel/security/tlsm/"
SYSFS_ADDPOLICY = join(SYSFS_ROOT, "add_policy")
SYSFS_LIST = join(SYSFS_ROOT, "list_policies")

def create_folders():
    mkdir(MAIN_FOLDER)

def add_policy(policy: str):
    try:
        f = open(SYSFS_ADDPOLICY, "w")
        print("Installing policy :", policy)
        f.write(policy)
        f.close()
    except OSError:
        print("Failed to open", SYSFS_ADDPOLICY, " - Is TLSM loaded ?")
        return -1

def apply_policies():
    print("Loading policies from", policies_path)
    try:
        policies = open(policies_path, "r")
        for i in policies.readlines():
            if i[0] == "@":
                pol = i[1:]
                add_policy(pol)
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
    print("usage: tlsm-py [ apply | list | add \"<policy>\"]")
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
        else:
            print_help()
    else:
        print_help()
    
    exit(0)