mov eax, dword ptr [0x600000]   ; eax = var1
mov ecx, dword ptr [0x600004]   ; ecx = var2

neg ecx                         ; ecx = -var2
imul eax, ecx                   ; eax = var1 * -var2

mov ecx, dword ptr [0x600008]   ; ecx = var3
sub ecx, ebx                    ; ecx = var3 - ebx

cdq                             ; sign extend
idiv ecx                        ; eax = (var1 * -var2) / (var3 - ebx)
mov dword ptr [0x600008], eax   ; var3 = (var1 * -var2) / (var3 - ebx)