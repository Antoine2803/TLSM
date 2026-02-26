#!/usr/bin/python
from time import sleep
import os
import signal

SIGNAL = signal.SIGTERM
DELAY = 2

def sig_handler(signum, frame):
    print(f"Received signal {signum}.")

signal.signal(SIGNAL, sig_handler)

print(f"This script tries to send signal {SIGNAL} to itself every {DELAY} seconds")

while True: 
    try:
        os.kill(os.getpid(), SIGNAL)
    except BaseException as e:
        print("Couldn't send signal : ", e)
    sleep(DELAY)