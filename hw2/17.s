mov dword ptr [0x600000], 1     ; var1 = 1
cmp eax, 0                  
jg _1                       
mov dword ptr [0x600000], -1    ; if eax < 0, var1 = -1

_1: 
mov dword ptr [0x600004], 1     ; var2 = 1
cmp ebx, 0
jg _2
mov dword ptr [0x600004], -1    ; if ebx < 0, var2 = -1

_2: 
mov dword ptr [0x600008], 1     ; var3 = 1
cmp ecx, 0
jg _3
mov dword ptr [0x600008], -1    ; if ecx < 0, var3 = -1

_3: 
mov dword ptr [0x60000C], 1     ; var4 = 1
cmp edx, 0
jg _4
mov dword ptr [0x60000C], -1    ; if edx < 0, var4 = -1

_4: