mov rax, 1          ; rax = r(n-1)
mov rbx, 0          ; rbx = r(n-2)
mov rdx, 25         ; n

lp:                 ; 3rbx + 2rax = rcx
    mov rcx, rax    ; store r(n-1) in rcx
    imul rbx, 3     ; rbx = 3*rbx  
    imul rax, 2     ; rax = 2*rax
    add rax, rbx    ; rax = 2*rax + 3*rbx = r(n)
    mov rbx, rcx    ; load r(n-1) into rbx 

    dec rdx         ; rdx--
    cmp rdx, 1
    jne lp