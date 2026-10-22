#!/usr/bin/env python3
"""Real-mode IPX ABI, scatter/gather, ESRs and UDP relay transport in QEMU."""
from pathlib import Path
import subprocess
import tempfile
from lan_fixture import LanPair
ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
bits 16
org 100h
mov ax,7a00h
int 2fh
cmp al,0ffh
jne fail
mov [driver],di
mov [driver+2],es
xor bx,bx
xor ax,ax
mov dx,9c86h
call far [driver]
test al,al
jnz fail
cmp dx,9c86h
jne fail
xor bx,bx
xor ax,ax
mov dx,9c86h
call far [driver]
cmp al,0ffh
jne fail
push ds
pop es
mov si,address
mov bx,9
int 7ah
mov ax,ds
mov [rx+6],ax
mov [rx+38],ax
mov [rx+44],ax
mov [tx+38],ax
mov [tx+44],ax
mov si,rx
mov bx,4
call far [driver]
test al,al
jnz fail
cmp byte [rx+8],0feh
jne fail
mov si,tx
mov bx,3
call far [driver]
test al,al
jnz fail
cmp byte [tx+8],0
jne fail
cmp byte [tx+9],0
jne fail
mov bp,20000
.wait:
mov bx,0ah
call far [driver]
cmp byte [callbacks],1
je .received
dec bp
jnz .wait
jmp fail
.received:
cmp byte [rx+8],0
jne fail
cmp byte [rx+9],0
jne fail
cmp dword [payload], 'PONG'
jne fail
; Cancellation clears the receive flag without an ESR.
mov word [rx+4],0
mov word [rx+6],0
mov si,rx
mov bx,4
call far [driver]
mov bx,6
call far [driver]
test al,al
jnz fail
cmp byte [rx+9],0fch
jne fail
cmp byte [rx+8],0
jne fail
; Malformed descriptors must not touch arbitrary guest memory.
mov word [tx+34],33
mov si,tx
mov bx,3
call far [driver]
cmp byte [tx+9],0fdh
jne fail
mov word [tx+34],2
; An asynchronous event also invokes its real-mode completion handler.
mov word [rx+4],esr
mov ax,ds
mov [rx+6],ax
mov ax,1
mov bx,5
mov si,rx
call far [driver]
mov bp,20000
.event:
mov bx,0ah
call far [driver]
cmp byte [callbacks],2
je .done
dec bp
jnz .event
jmp fail
.done:
mov bx,1
mov dx,9c86h
call far [driver]
mov dx,passed
mov ah,9
int 21h
mov ax,4c00h
int 21h
fail:
mov ax,4c01h
int 21h
esr:
cmp byte [cs:callbacks],0
jne .timer
cmp al,0ffh
jne fail
jmp .valid
.timer:
test al,al
jnz fail
.valid:
; Deliberately clobber volatile registers; the driver must restore them.
inc byte [cs:callbacks]
xor ax,ax
xor bx,bx
xor cx,cx
xor dx,dx
xor si,si
xor di,di
xor bp,bp
retf
passed db 'IPX-ABI-PASS',13,10,'$'
driver dd 0
callbacks db 0
address times 10 db 0
rx:
dd 0
dw esr,0
db 0,0
dw 9c86h
times 16 db 0
times 6 db 0
dw 2
dw header,0,30
dw payload,0,64
tx:
dd 0,0
db 0,0
dw 9c86h
times 16 db 0
times 6 db 0
dw 2
dw outgoing,0,30
dw ping,0,4
outgoing:
dw 0ffffh
db 0,34,0,4
dd 0
times 6 db 0ffh
dw 9c86h
times 12 db 0
ping db 'PING'
header times 30 db 0
payload times 64 db 0
'''


def run(*args):
    subprocess.run(list(map(str,args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


ECHO = r'''
bits 16
org 100h
mov ax,7a00h
int 2fh
cmp al,0ffh
jne fail
xor bx,bx
xor ax,ax
mov dx,9c86h
int 7ah
push ds
pop es
mov ax,ds
mov [ecb+38],ax
listen:
mov si,ecb
mov bx,4
int 7ah
waiting:
cmp byte [ecb+8],0
jne waiting
mov si,packet+18
mov di,packet+6
mov cx,5
rep movsw
mov dword [packet+30],'PONG'
mov bx,3
mov si,ecb
int 7ah
jmp listen
fail:
mov ax,4c01h
int 21h
ecb:
dd 0,0
db 0,0
dw 9c86h
times 16 db 0
times 6 db 0
dw 1
dw packet,0,34
packet times 34 db 0
'''
def main():
    run('bazelisk','build','//:boot_disk')
    with tempfile.TemporaryDirectory(prefix='retroos-ipx-') as folder:
        work = Path(folder)
        for name,code in [('PROBE',PROBE),('ECHO',ECHO)]:
            source = work/(name+'.asm')
            source.write_text(code)
            run('nasm','-f','bin','-o',work/(name+'.COM'),source)
        data = work/'data.img'
        with data.open('wb') as stream: stream.truncate(16*1024*1024)
        run('mkfs.fat','-F','16',data)
        for name in ('PROBE.COM','ECHO.COM'): run('mcopy','-i',data,work/name,'::/')
        pair = LanPair.__new__(LanPair)
        try:
            pair.__init__(work,data,['PROBE.COM','ECHO.COM'])
            pair.start()
            pair.wait(lambda: 'IPX-ABI-PASS' in pair.text(0),30)
            print('PASS: IPX discovery, far calls/INT 7A, UDP LAN, fragments, ESR, cancellation and events')
        finally: pair.close()
if __name__=='__main__': main()
