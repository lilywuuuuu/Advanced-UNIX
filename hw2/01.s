mov eax, dword ptr [0x600000]   ; eax = var1
mov ebx, dword ptr [0x600004]   ; ebx = var2
mov ecx, dword ptr [0x600008]   ; ecx = var3
add eax, ebx                    ; eax = var1 + var2
sub eax, ecx                    ; eax = var1 + var2 - var3
mov dword ptr [0x60000c], eax   ; final = var1 + var2 - var3
