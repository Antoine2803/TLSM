#!/usr/bin/python

from os import mkdir, getuid, listdir, getpid
from os.path import join, isfile, isdir
from sys import argv
from time import sleep
import signal

SYSFS_ROOT = "/sys/kernel/security/tlsm/"
WATCHDOG_REGISTER_ENDPOINT = join(SYSFS_ROOT, "add_watchdog")
USER_REQUEST_PATH = join(SYSFS_ROOT, "user_" + str(getuid()))

def register_watchdog(uid):
    try:
        print(f"registering watchdog for user {uid} via securityfs")
        f = open(WATCHDOG_REGISTER_ENDPOINT, 'w')
        f.write(f"{getpid()} {uid}")
        f.close()    
    except Exception as e:
        print("failed to register watchdog", str(e))

def answer_request(path, value):
    try:
        print("answering request via securityfs")
        f = open(path, 'w')
        f.write(str(value))
        f.close()
    except Exception as e:
        print(f"failed to write to request file {path}. Request probably timed out", str(e))

def process_request(path):
    print("got request: ", path)
    answer = input("deny ? 0 (n) / 1 (y):\n")
    print("got answer", answer)
    answer_request(path, answer)

def request_scan(user_request_fpath):
    files = [ join(user_request_fpath, f) for f in listdir(user_request_fpath) if isfile(join(user_request_fpath, f))]
    for f in files:
        print("found request file", f)
        process_request(f)

def sig_handler(signum, frame):
  print("SIGNAL FROM KERNEL, new events !", signum, str(frame))
  request_scan(USER_REQUEST_PATH)


def watchdog(uid: int):
    while True:
        if isdir(USER_REQUEST_PATH):
            request_scan(USER_REQUEST_PATH)
        else:
            print(f"tlsmd: {USER_REQUEST_PATH} folder does not exist yet")
        sleep(5) # busy-wait relief


def main():
    uid = getuid()
    print("TLSMD running for user", uid)
    register_watchdog(uid)
    signal.signal(signal.SIGUSR1, sig_handler)
    while True:
        sleep(10)
        print("still alive")

if __name__ == '__main__':
    main()