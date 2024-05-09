mov eax, dword ptr [0x600000]   ; eax = var1
mov ebx, dword ptr [0x600004]   ; ebx = var2
mov ecx, dword ptr [0x600008]   ; ecx = var3
neg eax                         ; eax = -var1
imul eax, ebx                   ; eax = -var1 * var2
add eax, ecx                    ; eax = (-var1 * var2) + var3