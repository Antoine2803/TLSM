#!/usr/bin/python

from os import mkdir, getuid, listdir
from os.path import join, isfile
from sys import argv
from time import sleep
import pyinotify

SYSFS_ROOT = "/sys/kernel/security/tlsm/"

def answer_request(path, value):
    f = open(path, 'w')
    f.write(str(value))
    f.close()

def process_request(path):
    print("got request: ", path)
    answer = input("approve ? 0/1\n")
    print("got answer", answer)
    answer_request(path, answer)

class MyEventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        print("inotify got request")
        process_request(event.pathname)

def manual_scan(user_request_fpath):
    files = [ join(user_request_fpath, f) for f in listdir(user_request_fpath) if isfile(join(user_request_fpath, f))]
    for f in files:
        print("manual scan found pending request")
        process_request(f)

def monitor_securitfs(uid: int):
    user_request_fpath = join(SYSFS_ROOT, "user_" + str(uid))
    
    wm = pyinotify.WatchManager()
    handler = MyEventHandler()
    notifier = pyinotify.Notifier(wm, handler)
    mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_DELETE
    wdd = None
    while (not wdd) or (list(wdd.values())[0] != 1):    
        if wdd != None:
                sleep(1)
        print("trying to add folder")
        wdd = wm.add_watch(user_request_fpath, mask, rec=True)  # rec=True for recursive monitoring
    
    # workaround: we create the folder at the moment we got the first request
    # So inotify will probably not catch the first file creation event.
    manual_scan(user_request_fpath)


    try:
        print("inotify monitoring up and running")
        notifier.loop()
    except pyinotify.NotifierError as err:
        print(err)
    finally:
        wm.rm_watch(wdd.values()) # Remove all watches






def main():
    uid = getuid()
    print("TLSMD running for user", uid)
    monitor_securitfs(uid)

if __name__ == '__main__':
    main()