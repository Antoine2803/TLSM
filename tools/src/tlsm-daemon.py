#!/usr/bin/python


from os import mkdir, getuid, listdir, getpid
from os.path import join, isfile, isdir
from sys import argv
from time import sleep
from queue import Queue, Full, ShutDown
import signal
import threading


SYSFS_ROOT = "/sys/kernel/security/tlsm/"
WATCHDOG_REGISTER_ENDPOINT = join(SYSFS_ROOT, "add_watchdog")
USER_REQUEST_PATH = join(SYSFS_ROOT, "user_" + str(getuid()))

request_queue = Queue()

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
    answer = input("allow ? Y/n: ")
    print("got answer", answer)
    answer = '0' if answer in ['y', 'Y', ''] else '1'
    answer_request(path, answer)

def request_scan(user_request_fpath):
    files = [ join(user_request_fpath, f) for f in listdir(user_request_fpath) if isfile(join(user_request_fpath, f))]
    for f in files:
        print("found request file", f)
        try:
            request_queue.put_nowait(f)
        except Full:
            print("WARNING: request queue is full. request will be dropped")

def sig_handler(signum, frame):
  print("ERROR: Oops, something went wrong. This handler shouldn't have been called")

def watchdog(uid: int):
    while True:
        if isdir(USER_REQUEST_PATH):
            request_scan(USER_REQUEST_PATH)
        else:
            print(f"tlsmd: {USER_REQUEST_PATH} folder does not exist yet")
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
    print("TLSMD running for user", uid)
    t = threading.Thread(target=queue_worker)
    t.start()
    register_watchdog(uid)
    signal.signal(signal.SIGUSR1, sig_handler) # actually will never be called 
                                               # but necessary because not binding a handler 
                                               # exits the program on reception of the signal
    while True:
        try:
            info = signal.sigwaitinfo([signal.SIGUSR1])
            try:
                request_queue.put_nowait(info.si_status)
            except Full:
                print("WARNING: request queue is FULL ! request will be lost !")
        except InterruptedError:
            print("We were interrupted!")
            break

    t.join()
    print("Goodbye.")

if __name__ == '__main__':
    main()