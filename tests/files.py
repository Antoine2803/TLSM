#!/usr/bin/python
from time import sleep

FILE="/home/arch/.bashrc"

print(f"This script tries to open {FILE}")

while True:
    try:
        f = open(FILE)
        print("open ok")
        f.close()
    except Exception as e:
        print("open ko, got", e)

    sleep(2)