mov eax, dword ptr [0x600000]   ; eax = var1
mov ebx, dword ptr [0x600004]   ; ebx = var2

imul eax, 5                     ; eax = var1 * 5
sub ebx, 3                      ; ebx = var2 - 3
idiv ebx                        ; eax = (var1 * 5) / (var2 - 3)
mov dword ptr [0x600008], eax   ; var4 = (var1 * 5) / (var2 - 3)