#!/usr/bin/python
from socket import *

with socket(AF_INET, SOCK_STREAM) as s:
    s.connect(('localhost', 2000))
    s.sendall(b'Hello World')

    data = s.recv(1024)

print(f"received {data!r}")
