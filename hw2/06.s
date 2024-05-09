mov eax, dword ptr [0x600000]   ; eax = Xval
mov ebx, dword ptr [0x600004]   ; ebx = Yval
mov ecx, dword ptr [0x600008]   ; ecx = Zval
neg eax                         ; eax = -Xval
sub ebx, ecx                    ; ebx = Yval - Zval
add eax, ebx                    ; eax = -Xval + Yval - Zval
mov dword ptr [0x60000c], eax   ; Rval = -Xval + Yval - Zval