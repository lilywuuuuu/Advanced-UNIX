mov eax, dword ptr [0x600004]   ; eax = var2
mov ebx, dword ptr [0x600008]   ; ebx = var3
mov ecx, dword ptr [0x600000]   ; ecx = var1

neg eax                         ; -var2
cdq                             ; sign extend
idiv ebx                        ; edx = -var2 % var3
mov ebx, edx                    ; ebx = -var2 % var3
imul ecx, -5                    ; var1 * -5
mov eax, ecx                    ; eax = var1 * -5
cdq                             ; sign extend
idiv ebx                        ; eax = (var1 * -5) / (-var2 % var3)
mov dword ptr [0x60000c], eax   ; var4 = (var1 * -5) / (-var2 % var3)