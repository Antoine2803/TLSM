#!/usr/bin/python

from os import mkdir, getuid, listdir, getpid, write
from os.path import join, isfile, isdir
from sys import argv, stdout, stdin
from time import sleep
from queue import Queue, Full, ShutDown
import signal
import threading
import subprocess
import termios

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
TAG_REQ = term_colors.BOLD + term_colors.OKGREEN + "[REQ]" + term_colors.ENDC
TAG_REQD = term_colors.BOLD + term_colors.FAIL + "[REQ]" + term_colors.ENDC

SYSFS_ROOT = "/sys/kernel/security/tlsm/"
WATCHDOG_REGISTER_ENDPOINT = join(SYSFS_ROOT, "add_watchdog")
USER_REQUEST_PATH = join(SYSFS_ROOT, "user_" + str(getuid()))

request_queue = Queue()

def send_notify(req_str: str):
    try:
        subprocess.run(["/usr/bin/notify-send", 
                    "--app-name=TLSMD",
                    "--icon=info", 
                    "Your attention is required :\n" + req_str])
    except Exception as e:
        print(f"{TAG_WARN} libnotify failed. cannot send desktop notification. ({e})")

def register_watchdog(uid):
    try:
        print(f"{TAG_INFO} Registering watchdog for user {uid} via securityfs")
        f = open(WATCHDOG_REGISTER_ENDPOINT, 'w')
        f.write(f"{getpid()} {uid}")
        f.close()    
    except Exception as e:
        print(f"{TAG_ERR} Failed to register watchdog", str(e))

def answer_request(path, value):
    try:
        print(f"{TAG_INFO} Answering request via securityfs")
        f = open(path, 'w')
        f.write(str(value))
        f.close()
    except Exception as e:
        print(f"{TAG_WARN} Failed to write to request file {path}. Request probably timed out\n", str(e))

def process_request(path):
    print(f"{TAG_REQ} Got request: ", path)
    try:
        with open(path) as f:
            req_str = f.read().strip('\n')
            print(term_colors.BOLD + "-> " + req_str + term_colors.ENDC)
            send_notify(req_str)

        termios.tcflush(stdin, termios.TCIOFLUSH) # flush stdin before input
        answer = input(f"{term_colors.BOLD}Allow ? y/n{term_colors.ENDC}: ")
        answer = '0' if answer in ['y', 'Y', ''] else '1'
        if answer == '1':
            print(f"{TAG_REQD} DENYING REQUEST")
        else:
            print(f"{TAG_REQ} ALLOWING REQUEST")
        answer_request(path, answer)
    except Exception as e:
        print(f"{TAG_ERR} Failed to open request file, probably timeout. {e}")

def request_scan(user_request_fpath):
    files = [ join(user_request_fpath, f) for f in listdir(user_request_fpath) if isfile(join(user_request_fpath, f))]
    for f in files:
        print("Found request file", f)
        try:
            request_queue.put_nowait(f)
        except Full:
            print(f"{TAG_WARN} Request queue is full. request will be dropped")

def sig_handler(signum, frame):
    write(stdout.fileno(), b"[ERROR] Oops, something went wrong. This handler shouldn't have been called")

def watchdog(uid: int):
    while True:
        if isdir(USER_REQUEST_PATH):
            request_scan(USER_REQUEST_PATH)
        else:
            print(f"{TAG_WARN} tlsmd: {USER_REQUEST_PATH} folder does not exist yet")
        sleep(5) # busy-wait relief

def queue_worker():
    while not request_queue.is_shutdown:
        try:
            req = request_queue.get()
            process_request(join(USER_REQUEST_PATH, f"request_{req}"))
        except ShutDown:
            break

def main():
    uid = getuid()
    print(f"{TAG_INFO} TLSMD running for user", uid)
    t = threading.Thread(target=queue_worker)
    t.start()
    register_watchdog(uid)
    signal.signal(signal.SIGUSR1, sig_handler) # actually will never be called 
                                               # but necessary because not binding a handler 
                                               # exits the program on reception of the signal
    try:
        while True:
            try:
                info = signal.sigwaitinfo([signal.SIGUSR1])
                try:
                    if info.si_pid == 0 and info.si_uid==0: #ensuring the signal has been sent by the kernel
                        request_queue.put_nowait(info.si_status)
                except Full:
                    print(stdout, f"{TAG_WARN} request queue is FULL ! request will be lost !")
            except InterruptedError:
                print("We were interrupted!")
                break
    except KeyboardInterrupt as e:
        print(f"{TAG_INFO} received " + str(e))
        request_queue.shutdown()
        t.join()
    
    print(term_colors.BOLD + "Goodbye." + term_colors.ENDC)

if __name__ == '__main__':
    main()