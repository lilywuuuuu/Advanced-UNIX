#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import sys
import math
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break
    print(time.time(), "done.")
    r.sendlineafter(b'string S: ', base64.b64encode(solved))

num0 = [" ┌───┐ ", 
        " │   │ ", 
        " │   │ ", 
        " │   │ ", 
        " └───┘ "]
num1 = ["  ─┐   ", 
        "   │   ", 
        "   │   ", 
        "   │   ", 
        "  ─┴─  "]
num2 = [" ┌───┐ ", 
        "     │ ", 
        " ┌───┘ ", 
        " │     ", 
        " └───┘ "]
num3 = [" ┌───┐ ", 
        "     │ ", 
        "  ───┤ ", 
        "     │ ", 
        " └───┘ "]
num4 = [" │   │ ", 
        " │   │ ", 
        " └───┤ ", 
        "     │ ", 
        "     │ "]
num5 = [" ┌──── ", 
        " │     ", 
        " └───┐ ", 
        "     │ ", 
        " └───┘ "]
num6 = [" ┌───┐ ", 
        " │     ", 
        " ├───┐ ", 
        " │   │ ", 
        " └───┘ "]
num7 = [" ┌───┐ ", 
        " │   │ ", 
        "     │ ", 
        "     │ ", 
        "     │ "]
num8 = [" ┌───┐ ", 
        " │   │ ", 
        " ├───┤ ", 
        " │   │ ", 
        " └───┘ "]
num9 = [" ┌───┐ ", 
        " │   │ ", 
        " └───┤ ", 
        "     │ ", 
        " └───┘ "]
add =  ["       ", 
        "   │   ", 
        " ──┼── ", 
        "   │   ", 
        "       "]
div  = ["       ", 
        "   •   ", 
        " ───── ", 
        "   •   ", 
        "       "]
multi =["       ", 
        "  ╲ ╱  ", 
        "   ╳   ", 
        "  ╱ ╲  ", 
        "       "]

check = [num0, num1, num2, num3, num4, num5, num6, num7, num8, num9, add, multi, div]

def number_recognition(num):
    for i in range(13):
        # print(num)
        # print(check[i])
        if num == check[i]:
            if i < 10:
                return str(i)
            elif i == 10:
                return '+'
            elif i == 11:
                return '*'
            elif i == 12:
                return '/'
            
def solve(code):
    decoded_code = base64.b64decode(code).decode()
    print(decoded_code)
    length = math.floor(len(decoded_code)/5/7)
    nums = []
    for i in range(length):
        nums.append([])
        for j in range(5):
            nums[i].append(decoded_code[(7*length + 1)*j + i*7 : (7*length + 1)*j + i*7 + 7])
    
    ans = ""
    for i in range(length):
        ans += number_recognition(nums[i])
    ans = eval(ans)
    r.sendline(b"%d" % ans)

if __name__ == "__main__":
    r = None
    if len(sys.argv) == 2:
        r = remote('localhost', int(sys.argv[1]))
    elif len(sys.argv) == 3:
        r = remote(sys.argv[2], int(sys.argv[1]))
    else:
        r = process('./pow.py')
    solve_pow(r)
    
    msg = r.recvuntil(b'? ').decode()
    print(msg)
    parts = msg.split()
    for part in parts:
        if len(part) > 100: 
            code = part
        if part.isdigit():
            count = int(part)
    solve(code)
    for i in range(count-1):
        msg = r.recvuntil(b'? ').decode()
        print(msg)
        parts = msg.split()
        for part in parts:
            if len(part) > 100: 
                code = part
        solve(code)

    r.interactive()