bits 32
section .text
global PlaySoundW
; No Windows PCM backend is registered. Do not claim successful playback.
PlaySoundW:
    xor eax,eax
    ret 12
