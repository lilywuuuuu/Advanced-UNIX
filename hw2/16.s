mov eax, dword ptr [0x600000]   ; eax = val1
imul eax, 26                    ; eax = val1 * 26
mov dword ptr [0x600004], eax   ; val2 = val1 * 26