#!/usr/bin/python
from socket import *

with socket(AF_INET, SOCK_STREAM) as se:
    se.bind(('localhost',  2000))
    se.listen()
    
    conn, addr = se.accept()
    with conn:
        print(f"connected to {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)


