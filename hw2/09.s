mov ecx, 15             ; Counter for the loop
mov esi, 0x600000       ; Source string
mov edi, 0x600010       ; Destination string

convert_loop:
    mov al, byte ptr [esi] ; Load a character from str1
    cmp al, 90             ; Compare it with 'Z'
    jg lowercase           ; If it's less than 'Z', it's already lowercase
    add al, 32             ; Otherwise, add 32 to convert it to lowercase
lowercase:
    mov byte ptr [edi], al ; Store the character in str2
    inc esi                ; Move to the next character in str1
    inc edi                ; Move to the next position in str2
    loop convert_loop      ; Decrement ecx and loop if it's not zero