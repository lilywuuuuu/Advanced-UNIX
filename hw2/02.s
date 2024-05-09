mov esi, 0
mov ebp, 10 ; loop counter
lp2:
    cmp ebp, 0 ; finished loop
    je end
    mov ecx, 0x600000 ; arr[0]
    mov edx, 0x600004 ; arr[1]
    lp1:
        mov eax, dword ptr [ecx]
        mov ebx, dword ptr [edx]
        cmp eax, ebx
        jng skip ; correct order
        swap:
        mov dword ptr [ecx], ebx
        mov dword ptr [edx], eax
        skip:
        add ecx, 4
        add edx, 4
        cmp ecx, 0x600024
        jne lp1
        dec ebp
        jmp lp2
end: