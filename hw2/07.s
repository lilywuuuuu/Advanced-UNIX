shr ax, 5                   ; shift right by 5 bits   
and ax, 0b1111111           ; keep only bit-11 ~ bit-5
mov byte ptr [0x600000], al ; store result to only one byte