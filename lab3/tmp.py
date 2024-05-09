from pwn import *
elf = ELF('./maze')
print("main =", hex(elf.symbols['main']))
print("{", end="")
# print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
for s in [ f"move_{i}" for i in range(1200)]:
   if s in elf.got:
      # print("{:<12s} {:<10x} {:<10x}".format(s, elf.got[s], elf.symbols[s]))
      print(hex(elf.got[s]), end=", ")
print("}", end="")