mov cx, 16          ; Loop counter
mov bx, ax          ; Copy ax to bx for shifting
mov edi, 0x60000f   ; Destination string

convert_loop:
    mov byte ptr [edi], 48 ; Assume the bit is 0 and store '0'
    mov dx, bx             ; Copy bx to dx for shifting
    and dl, 1              ; Isolate the least significant bit
    cmp dl, 0              ; Compare it with 0
    je next                ; If it's 0, skip to next
    mov byte ptr [edi], 49 ; Otherwise, store '1'
next:
    shr bx, 1              ; Shift bx right by 1 bit
    dec edi                ; Move to the next position in the string
    loop convert_loop      ; Decrement cx and loop if it's not zero