---
title: BuckeyCTF - befuddled
categories: [ctf2025, buckeyCTF]
tags: [reverse, vm, unicorn, gdb]
---

最近闲来无事，又翻出了这一道题。起初我尝试用gdb脚本解，但是只解出了最后几个字符；后来看discord群里有大佬是用unicorn做的，也体验了一下这个工具，发现确实挺不错的。

### 0x01 gdb脚本尝试
刚拿到程序，发现是一个stack vm，含有大量gadget 函数
```
.text:00000000004013E0
.text:00000000004013E1
.text:00000000004013E1                         ; =============== S U B R O U T I N E =======================================
.text:00000000004013E1
.text:00000000004013E1                         ; Attributes: noreturn
.text:00000000004013E1
.text:00000000004013E1                         ; void __fastcall __noreturn main(int, char **, char **)
.text:00000000004013E1                         main            proc near               ; DATA XREF: start+18↑o
.text:00000000004013E1
.text:00000000004013E1                         var_1000        = byte ptr -1000h
.text:00000000004013E1
.text:00000000004013E1 48 81 EC 00 10 00 00                    sub     rsp, 1000h
.text:00000000004013E8 48 8D 3C 24                             lea     rdi, [rsp+1000h+var_1000]
.text:00000000004013EC 48 C7 C1 00 10 00 00                    mov     rcx, 1000h
.text:00000000004013F3 30 C0                                   xor     al, al
.text:00000000004013F5 F3 AA                                   rep stosb
.text:00000000004013F7 4D 31 E4                                xor     r12, r12
.text:00000000004013FA E9 3E 03 00 00                          jmp     loc_40173D
.text:00000000004013FF                         ; ---------------------------------------------------------------------------
.text:00000000004013FF E8 A9 FF FF FF                          call    offset_add_5014
.text:0000000000401404 E8 C4 FF FF FF                          call    deref_r12_add
.text:0000000000401409 E8 9F FF FF FF                          call    offset_add_5014
.text:000000000040140E E8 BA FF FF FF                          call    deref_r12_add
.text:0000000000401413 E8 95 FF FF FF                          call    offset_add_5014
.text:0000000000401418 E8 B0 FF FF FF                          call    deref_r12_add
.text:000000000040141D E8 8B FF FF FF                          call    offset_add_5014
.text:0000000000401422 E8 A6 FF FF FF                          call    deref_r12_add
.text:0000000000401427 E8 81 FF FF FF                          call    offset_add_5014
.text:000000000040142C E8 9C FF FF FF                          call    deref_r12_add
.text:0000000000401431 E8 77 FF FF FF                          call    offset_add_5014
.text:0000000000401436 E8 92 FF FF FF                          call    deref_r12_add
.text:000000000040143B E8 6D FF FF FF                          call    offset_add_5014
.text:0000000000401440 E8 88 FF FF FF                          call    deref_r12_add
.text:0000000000401445 E8 63 FF FF FF                          call    offset_add_5014
```
把gadget函数丢给GPT分析：
```
| 0x401126       | 压入0（类似PUSH 0）                   | push_0              |
| 0x40112D       | 压入1                                 | push_1              |
| 0x401134       | 压入2                                 | push_2              |
| 0x40113B       | 压入3                                 | push_3              |
| 0x401142       | 压入4                                 | push_4              |
| 0x401149       | 压入5                                 | push_5              |
| 0x401150       | 压入6                                 | push_6              |
| 0x401157       | 压入7                                 | push_7              |
| 0x40115E       | 压入8                                 | push_8              |
| 0x401165       | 压入9                                 | push_9              |
| 0x40116C       | 栈顶两数相加再压栈                    | add                 |
| 0x401177       | 栈顶两数相减再压栈                    | sub                 |
| 0x401182       | 栈顶两数相乘再压栈                    | mul                 |
| 0x40118E       | (访问特殊表qword_409018,加倍，加特定偏移处理) | deref_add_shift     |
| 0x4011A5       | 栈顶两数相除（被除数/除数），结果压栈,除数为0时压0 | div                 |
| 0x4011BE       | 栈顶两数取模，若除数为0则压0           | mod                 |
| 0x4011D7       | 判断栈顶是否为0，是则压入1，否则压入0    | iszero              |
| 0x4011E8       | if (第二个数 >= 第一个数)压1，否则压0   | ge (greater_equal)  |
| 0x4011FA       | 弹出一个数printf("%d\n")输出            | print_int           |
| 0x401219       | 向stdout写单字节(r12指向的值？)          | write_stdout        |
| 0x401242       | 从stdin读取1字节至栈                    | read_stdin          |
| 0x40126C       | r12=0                                  | set_r12_0           |
| 0x401278       | r12=1                                  | set_r12_1           |
| 0x401284       | r12=2                                  | set_r12_2           |
| 0x401290       | r12=3                                  | set_r12_3           |
| 0x40129C       | 判断栈顶是否为0，是则r12=0，否则r12=1    | set_r12_iszero      |
| 0x4012B7       | 判断栈顶是否为0，是则r12=2，否则r12=3    | set_r12_switch23    |
| 0x4012D2       | 复制一个栈顶数（双压栈）                | duplicate           |
| 0x4012DA       | 交换栈顶两个数                          | swap                |
| 0x4012E3       | 弹栈（无效果，只pop后回压r14）           | drop                |
| 0x4012E9       | 调用exit(0)退出                        | exit_0              |
| 0x4012FE       | 读取byte_409038的部分（类似字符串/表查表）| table_lookup        |
| 0x401316       | 存值到byte_409038，对应位置编码写回 及跳转相关操作 | table_store_patch_jmp |
| 0x401352       | 查qword_409018若干偏移，直到byte_409038为0x22 (34,'"')才停止 | string_read_until_22|
| 0x401388       | 空操作，返回                           | nop                 |
| 0x40138D       | r14-5+0x320，地址偏移运算               | offset_add_320      |
| 0x40139D       | r14-5-0x320，地址偏移运算               | offset_sub_320      |
| 0x4013AD       | r14-5+0x5014，地址偏移运算              | offset_add_5014     |
| 0x4013BD       | r14-5-0x5014，地址偏移运算              | offset_sub_5014     |
| 0x4013CD       | 取qword_409018[r12*8]加到r14-0xa压栈     | deref_r12_add       |
```
其中的`read_stdin`和`write_stdout`负责IO，但是`print_int`函数似乎没有被引用（尽管存在一种可能：在某个函数ret前栈上填充一个值，指向某些特定的函数，但是概率比较小。我们可以暂时暂时假设：所有的ret都会回到标准的代码流程中，通过`call`来调用函数，时后证明确实如此）

函数的跳转机制主要通过查表决定，通常以`r12`为索引。

此时我还秉持古法调试的原则，在关键的gadget函数上下断点，拦截到了读取flag的逻辑，会以此将所有的字符都压入栈，当遇到换行符终止读取并开始判断。

随后给相关的数据下硬件断点，找到了比较逻辑（通过`Sub`完成）

然后整了一版gdb脚本（前面的几版已经丢了...）：

```python
import gdb

reversed_flag = ['}', '3', 'l', 'b', 'a', 'l', '1', 'p', 'm']
# reversed_flag = ['}']

while True:
    # preapare input file
    with open('./flag.txt', 'w') as f:
        curr_flag = ''.join(reversed_flag[::-1])
        # NOTE:
        # must add \n, other wise will fall in read loop!!!
        f.write('*'+curr_flag+'\n')      # write a trash val
        print(f'current flag: {curr_flag}')
    
    # clear all breakpoint and state var
    read_done = False

    for bp in gdb.breakpoints():
        bp.delete()
    print('<<<<<<<<<<<<<<<,')
    gdb.execute("i b")
    print('<<<<<<<<<<<<<<<,')

    # reset breakpoint
    gdb.execute("b *0x401269")
    # bp = gdb.Breakpoint("*0x401269", type=gdb.BP_BREAKPOINT, internal=False)
    print('running...')
    gdb.execute('run -a < ./flag.txt')

    while True:
        rsp = gdb.parse_and_eval("$rsp")
        curr_char = chr(rsp.cast(gdb.lookup_type('char').pointer()).dereference() & 0xFF)

        print('+++++++++++')
        print(curr_char)
        
        if(curr_char == '}'):  # the last char
            print(f'Stop at {hex(rsp)}')
            break

        gdb.execute("continue")

    # stop when [rsp] is the last char
    # now try to crack it in reverse order

    # set hardware bp
    rsp = gdb.parse_and_eval("$rsp")
    hd_bp_addr =  int(rsp) + 8*len(reversed_flag)
    hd_bp_spec = f'*{hex(hd_bp_addr)}'
    print(f'hbreak {hd_bp_spec}')

    print('setting hd_bp')
    gdb.execute(f'awatch {hd_bp_spec}')
    # gdb.Breakpoint(hd_bp_spec, type=gdb.BP_ACCESS_WATCHPOINT, internal=False)
    print('===========')

    # gdb.execute('continue') # we need to continue twice, first to execute read again(end with '\x0A')
    gdb.execute('continue') # pass the read of '\n'
    gdb.execute('continue') # trigger access watch point

    # now read the true val
    target_char = chr(int(gdb.parse_and_eval('$rdi') & 0xFF))
    reversed_flag.append(target_char)

    break

    
    if(target_char == '{'):
       print('======================')
       print(''.join(reversed_flag[::-1]))
       print('======================')
       break
# print flag
```
- gdb.breakpoints() 返回当前的断点列表
- 可以继承BreakPoint类，编写自己的断点类型，重写触发时的逻辑（不过后来的版本已经删掉了）
- gdb.execute("xxx") 可以执行命令
- gdb.parse_and_eval('$rdi') 可以获得寄存器的值
- gdb.execute(f'awatch {hd_bp_spec}') 下watch断点，当指定地址的内容被读写的时候会触发

基本思路是：在特定位置获得`rsp`的值，然后计算出参与判断的第一个字符位置，随后下`watchpoint`，等待触发，自动dump。然而只dump出了最后的

> 我当时假设所有的比较都是一样的逻辑（事实上后面有更复杂的逻辑，比如Mod + Div）；而且其中很多值的计算都依赖于调试的经验，健壮性很弱
{: .prompt-warning}

### 0x02 unicorn01： 映射
在自己的探索失败后，开始看discord。其中有一位大佬是用**unicorn**来打印出运行时的栈解决的，我也想凑这个机会学习一下unicorn的用法

初版（映射存在问题）：
```python
from unicorn import *
from unicorn.x86_const import *

from pwn import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)


BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)

# 写入内存
mu.mem_write(BASE, read("./befuddled"))
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE)   # set stack ptr

sample1 = mu.mem_read(0x409018, 0x20)
print(sample1.hex())
def dump_regs(uc: Uc):
    regs = [
        ("RAX", UC_X86_REG_RAX),
        ("RBX", UC_X86_REG_RBX),
        ("RCX", UC_X86_REG_RCX),
        ("RDX", UC_X86_REG_RDX),
        ("RSI", UC_X86_REG_RSI),
        ("RDI", UC_X86_REG_RDI),
        ("RBP", UC_X86_REG_RBP),
        ("RSP", UC_X86_REG_RSP),
        ("R8",  UC_X86_REG_R8),
        ("R9",  UC_X86_REG_R9),
        ("R10", UC_X86_REG_R10),
        ("R11", UC_X86_REG_R11),
        ("R12", UC_X86_REG_R12),
        ("R13", UC_X86_REG_R13),
        ("R14", UC_X86_REG_R14),
        ("R15", UC_X86_REG_R15),
        ("RIP", UC_X86_REG_RIP),
        ("EFLAGS", UC_X86_REG_EFLAGS),
    ]
    for name, r in regs:
        val = uc.reg_read(r)
        print(f"{name:6} = 0x{val:016x}")

def hook_code(mu : Uc, address, size, user_data):  
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

    dump_regs(mu)
    rsp_val = mu.reg_read(UC_X86_REG_RSP)
    instr_bytes = mu.mem_read(address, size)
    print(f'instr {instr_bytes.hex()}')

    if rsp_val < STACK_SIZE - 40:
        print(f'{hex(rsp_val)} Stack: {[mu.mem_read(rsp_val + 8*i, 8) for i in range(5)]}')
    print('')

mu.hook_add(UC_HOOK_CODE, hook_code)

# 启动
mu.emu_start(0x4013E1, 0x401B89)
```
将二进制文件读取到BASE开始的地址上（和ida中的起始地址保持一致，因为ida就是通过解析文件头来获得各个段的加载地址的），栈的地址可以随意设置。最后`mu.emu_start`设置启动地址和终止地址，这里分别对应`main`函数的开始和结束。

然而，运行的时候报错，通过`hook_code`打印出信息，发现问题出在：
```
.text:00000000004013CD                         ; void __fastcall deref_r12_add()
.text:00000000004013CD                         deref_r12_add   proc near               ; CODE XREF: main+23↓p
.text:00000000004013CD                                                                 ; main+2D↓p ...
.text:00000000004013CD 41 5E                                   pop     r14
.text:00000000004013CF 4A 8B 14 E5 18 90 40 00                 mov     rdx, qword_409018[r12*8]
.text:00000000004013D7 49 83 EE 0A                             sub     r14, 0Ah
.text:00000000004013DB 49 01 D6                                add     r14, rdx
.text:00000000004013DE 41 56                                   push    r14
.text:00000000004013E0 C3                                      retn
.text:00000000004013E0                         deref_r12_add   endp
```
中的`mov     rdx, qword_409018[r12*8]`一步，正常结果应该是5,但是这里却得到了错误的地址。

随后使用`mu.mem_read`读取这里的地址，确实是错误的。但是，问题出在哪里呢？

回想起整个操作中最令我疑惑的地方，莫过于`mu.mem_write(BASE, read("./befuddled"))`这一步，真的能够直接把raw binary file直接加载到执行时的内存中吗？

检查 ida/segments 窗口，
```
LOAD	0000000000400000	0000000000400500	R	.	.	.	L	mempage	0001	public	DATA	64	0000	0000	0014	0000	0000
.init	0000000000401000	000000000040101B	R	.	X	.	L	dword	0009	public	CODE	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
LOAD	000000000040101B	0000000000401020	R	W	X	.	L	mempage	0002	public	CODE	64	0000	0000	0014	0000	0000
.plt	0000000000401020	0000000000401040	R	.	X	.	L	para	000A	public	CODE	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.text	0000000000401040	0000000000406A7B	R	.	X	.	L	para	000B	public	CODE	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
LOAD	0000000000406A7B	0000000000406A7C	R	W	X	.	L	mempage	0002	public	CODE	64	0000	0000	0014	0000	0000
.fini	0000000000406A7C	0000000000406A89	R	.	X	.	L	dword	000C	public	CODE	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.rodata	0000000000407000	0000000000407808	R	.	.	.	L	dword	000D	public	CONST	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.eh_frame_hdr	0000000000407808	000000000040782C	R	.	.	.	L	dword	000E	public	CONST	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
LOAD	000000000040782C	0000000000407830	R	.	.	.	L	mempage	0003	public	DATA	64	0000	0000	0014	0000	0000
.eh_frame	0000000000407830	0000000000407898	R	.	.	.	L	qword	000F	public	CONST	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
LOAD	0000000000407898	0000000000407928	R	.	.	.	L	mempage	0003	public	DATA	64	0000	0000	0014	0000	0000
.init_array	0000000000408DF8	0000000000408E00	R	W	.	.	L	qword	0010	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.fini_array	0000000000408E00	0000000000408E08	R	W	.	.	L	qword	0011	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
LOAD	0000000000408E08	0000000000408FD8	R	W	.	.	L	mempage	0004	public	DATA	64	0000	0000	0014	0000	0000
.got	0000000000408FD8	0000000000408FE8	R	W	.	.	L	qword	0012	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.got.plt	0000000000408FE8	0000000000409008	R	W	.	.	L	qword	0013	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.data	0000000000409008	000000000040983A	R	W	.	.	L	qword	0014	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.bss	000000000040983A	0000000000409840	R	W	.	.	L	byte	0015	public	BSS	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	0014	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
extern	0000000000409840	0000000000409858	?	?	?	.	L	qword	0016	public		64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
```
但是我的二进制文件大小似乎并没有那么大。检查一下映射关系：
```
(venv14) woc@myarch:buckeyCTF/befuddled $ readelf -S befuddled
There are 29 section headers, starting at offset 0x8978:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note.gnu.pr[...] NOTE             0000000000400350  00000350
       0000000000000020  0000000000000000   A       0     0     8
  [ 2] .note.gnu.bu[...] NOTE             0000000000400370  00000370
       0000000000000024  0000000000000000   A       0     0     4
  [ 3] .interp           PROGBITS         0000000000400394  00000394
       000000000000001c  0000000000000000   A       0     0     1
  [ 4] .gnu.hash         GNU_HASH         00000000004003b0  000003b0
       000000000000001c  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004003d0  000003d0
       0000000000000060  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000400430  00000430
       000000000000004a  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040047a  0000047a
       0000000000000008  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400488  00000488
       0000000000000030  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             00000000004004b8  000004b8
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004004e8  000004e8
       0000000000000018  0000000000000018  AI       5    24     8
  [11] .init             PROGBITS         0000000000401000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000401020  00001020
       0000000000000020  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000401040  00001040
       0000000000005a3b  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         0000000000406a7c  00006a7c
       000000000000000d  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         0000000000407000  00007000
       0000000000000808  0000000000000000   A       0     0     4
  [16] .eh_frame_hdr     PROGBITS         0000000000407808  00007808
       0000000000000024  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000407830  00007830
       0000000000000068  0000000000000000   A       0     0     8
  [18] .note.ABI-tag     NOTE             0000000000407898  00007898
       0000000000000020  0000000000000000   A       0     0     4
  [19] .note.package     NOTE             00000000004078b8  000078b8
       0000000000000070  0000000000000000   A       0     0     4
  [20] .init_array       INIT_ARRAY       0000000000408df8  00007df8
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .fini_array       FINI_ARRAY       0000000000408e00  00007e00
       0000000000000008  0000000000000008  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000408e08  00007e08
       00000000000001d0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000408fd8  00007fd8
       0000000000000010  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000408fe8  00007fe8
       0000000000000020  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000409008  00008008
       0000000000000832  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           000000000040983a  0000883a
       0000000000000006  0000000000000000  WA       0     0     1
  [27] .comment          PROGBITS         0000000000000000  0000883a
       0000000000000026  0000000000000001  MS       0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00008860
       0000000000000114  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```
发现前面的一些段都满足`address = file offset + 0x400000`，但是从`0000000000408df8  00007df8`开始，就偏移了`0x1000`!

> TODO: 继续了解RVA和offset的关系

因此需要修改成：
```
raw_file = read("./befuddled")
mu.mem_write(BASE, raw_file[:0x7df8])
mu.mem_write(BASE + 0x8df8, raw_file[0x7df8:])
```

### 0x03 unicorn02：IO函数特判
修改后，程序能够正常跑起来了，但是无法停下来，应该是没有提供输入源的情况下，一直无法通过读取`\n`终止。

通过研究发现，gadget函数中和IO有关的（排除没有被调用的print_int）是通过read/write syscall完成的，这里使用capstone对指令解码判断，如果是相关的syscall,就在模拟器的层级代替其进行操作，并设置`RIP`跳过这一条指令（`mu.reg_write(UC_X86_REG_RIP, address + size)`）
```python
  class SimuStdin():
      data = "buckeyCTF{abcdefmp1labl3}\n"
      ptr = 0
      def getc(self):
          if self.ptr >= len(self.data):
              print('read data exceed bound!')
              exit(-2)
          result = self.data[self.ptr].encode()
          self.ptr += 1
          return result


  fake_stdin = SimuStdin()
  ......
  def hook_code(mu : Uc, address, size, user_data):  
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

    global global_counter
    code = mu.mem_read(address, size)

    # 2) Disassemble a single instruction
    for insn in md.disasm(bytes(code), address, count=1):
        # Print disassembled instruction (optional)
        # print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

        # 3) Check if it is "syscall"
        if insn.mnemonic == "syscall":
            # Read registers from Unicorn to identify syscall
            rax = mu.reg_read(UC_X86_REG_RAX)
            rdi = mu.reg_read(UC_X86_REG_RDI)
            rsi = mu.reg_read(UC_X86_REG_RSI)
            rdx = mu.reg_read(UC_X86_REG_RDX)

            if rax == SYS_READ:
                # skip this instr
                # and simu the stdin
                buf = rsi
                len = rdx
                c_byte = fake_stdin.getc()
                print('get: ')
                print(c_byte.decode())
                print('')
                mu.reg_write(UC_X86_REG_RIP, address + size)
                mu.mem_write(buf, c_byte)
            elif rax == SYS_WRITE:
                buf = rsi
                len = rdx
                data = mu.mem_read(buf, len)
                mu.reg_write(UC_X86_REG_RIP, address + size)
                print('===== STDOUT =====')
                print(data.decode())
                print('==================')
            else:
                print(f'unexpected syscall:{rax}')
                exit(-1)
    ......
```
至此，程序能够正常运行了，而且向我们输出了flag错误的信息

### 0x04 unicorn03：dump关键信息
我们目前位置的hook_code输出的信息难以分析，需要我们做出决策：要输出哪些指令的额外信息，以及忽略哪些指令？

在我的原始方法中，把所有的gadget function都考虑进去了，这引入了比较丑陋的地址查表、跳转逻辑。但是收到大神的启发，我开始尝试忽略那些无关紧要的东西，仅仅关注其中的**算数运算**，**push**,**cmp.zero/ge**，

```python
func_map = {
    0x401126: "push 0",
    0x40112D: "push 1",
    0x401134: "push 2",
    0x40113B: "push 3",
    0x401142: "push 4",
    0x401149: "push 5",
    0x401150: "push 6",
    0x401157: "push 7",
    0x40115E: "push 8",
    0x401165: "push 9",
    0x40116C: "Add",
    0x401177: "Sub",
    0x401182: "Mul",
    0x4011A5: "Div",
    0x4011BE: "Mod",
    0x4011D7: "cmp.zero",
    0x4011E8: "cmp.ge",
    0x4012D9: "dup",
    0x4012DA: "swap",
    0x4012E3: "drop"
}
```
然后需要计算虚拟机中的`call`指令地址进行比对：
```python
def hook_code(mu : Uc, address, size, user_data):  
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

    global global_counter
    code = mu.mem_read(address, size)

    # 2) Disassemble a single instruction
    for insn in md.disasm(bytes(code), address, count=1):
        if insn.mnemonic == "syscall":
            ......
        elif insn.mnemonic == "call":       # call指令，过滤特定函数
            print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}  <-- CALL")

            addr_value = None
            
                
            if insn.operands != None:
                op = insn.operands[0]
                if op.type == CS_OP_IMM:
                    addr_value = op.imm
            
            if addr_value:
                if addr_value in func_map.keys():
                    func_label = func_map[addr_value]
                    print('###', func_label, end='')
                    stack_sample(mu, 4)
                    print('--------------------------------')
        break  # we only disassembled 1 instruction
```
`call`指令分为：立即数跳转，寄存器跳转，内存跳转。我们这里只需要处理第一类即可


### 0x05 final：分析
每次不用完整将栈的值dump出来，只用保留4个。

测试：`bctf{abcdef}`，在读取最后的换行符后，可以看到后面会对`f`字符进行`Sub`判断，后面就会输出Nope，

```
......
0x404163: call 0x401290  <-- CALL
0x404168: call 0x4013cd  <-- CALL
0x403e34: call 0x4013cd  <-- CALL
0x403b00: call 0x4013cd  <-- CALL
0x4037c7: call 0x401134  <-- CALL
### push 2['3500000000000000', '6600000000000000', '6500000000000000', '6400000000000000']
[bytearray(b'5'), bytearray(b'f'), bytearray(b'e'), bytearray(b'd')]
--------------------------------
0x4037cc: call 0x4013cd  <-- CALL
0x403498: call 0x4013cd  <-- CALL
0x40315f: call 0x401177  <-- CALL
### Sub['0200000000000000', '3500000000000000', '6600000000000000', '6500000000000000']
[bytearray(b'\x02'), bytearray(b'5'), bytearray(b'f'), bytearray(b'e')]
--------------------------------
0x403164: call 0x4013cd  <-- CALL
0x402e30: call 0x4013cd  <-- CALL
0x402af7: call 0x401177  <-- CALL
### Sub['3300000000000000', '6600000000000000', '6500000000000000', '6400000000000000']
[bytearray(b'3'), bytearray(b'f'), bytearray(b'e'), bytearray(b'd')]
.......
```
这样一直向前推断，可以得到`mp1labl3`,这也是我自己最初的方法止步的地方。但是再往前就不是这么简单了，搜索`Sub`发现没有新的值，但是发现了`Mod`
(`data = "bctf{abcdefmp1labl3}\n"`)
```
### push 4['6600000000000000', '6600000000000000', '6500000000000000', '6400000000000000']
[bytearray(b'f'), bytearray(b'f'), bytearray(b'e'), bytearray(b'd')]
--------------------------------
0x403240: call 0x4013cd  <-- CALL
0x403574: call 0x4013cd  <-- CALL
0x4038a3: call 0x401142  <-- CALL
### push 4['0400000000000000', '6600000000000000', '6600000000000000', '6500000000000000']
[bytearray(b'\x04'), bytearray(b'f'), bytearray(b'f'), bytearray(b'e')]
--------------------------------
0x4038a8: call 0x4013cd  <-- CALL
0x403bdc: call 0x4013cd  <-- CALL
0x403f0b: call 0x40126c  <-- CALL
0x403f10: call 0x4013cd  <-- CALL
0x403f15: call 0x401290  <-- CALL
0x403f1a: call 0x4013cd  <-- CALL
0x403be6: call 0x4013cd  <-- CALL
0x4038ad: call 0x401182  <-- CALL
### Mul['0400000000000000', '0400000000000000', '6600000000000000', '6600000000000000']
[bytearray(b'\x04'), bytearray(b'\x04'), bytearray(b'f'), bytearray(b'f')]
--------------------------------
0x4038b2: call 0x4013cd  <-- CALL
0x40357e: call 0x4013cd  <-- CALL
0x403245: call 0x4011be  <-- CALL
### Mod['1000000000000000', '6600000000000000', '6600000000000000', '6500000000000000']
[bytearray(b'\x10'), bytearray(b'f'), bytearray(b'f'), bytearray(b'e')]
```
`Mod`校验不通过会终止，当符合这个约束后会再进行`Div`。但是继续就没什么花活儿了，就这两种套路，最后可以平推得到：
`bctf{c0mPIle_Th3_unC0mp1labl3}`

完整代码：
```python
from inspect import stack
import capstone
from unicorn import *
from unicorn.x86_const import *

from pwn import *

from capstone import CS_OP_IMM, Cs, CS_ARCH_X86, CS_MODE_64

# capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# try to hook read and write 
SYS_READ  = 0
SYS_WRITE = 1



mu = Uc(UC_ARCH_X86, UC_MODE_64)


BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)

# 写入内存
raw_file = read("./befuddled")
mu.mem_write(BASE, raw_file[:0x7df8])
mu.mem_write(BASE + 0x8df8, raw_file[0x7df8:])
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE)   # set stack ptr

# sample1 = mu.mem_read(0x409018, 0x20)
# print(sample1.hex())

class SimuStdin():
    data = "bctf{c0mPIle_Th3_unC0mp1labl3}\n"
    ptr = 0
    def getc(self):
        if self.ptr >= len(self.data):
            print('read data exceed bound!')
            exit(-2)
        result = self.data[self.ptr].encode()
        self.ptr += 1
        return result


fake_stdin = SimuStdin()

global_counter = 0;

# import function
func_map = {
    0x401126: "push 0",
    0x40112D: "push 1",
    0x401134: "push 2",
    0x40113B: "push 3",
    0x401142: "push 4",
    0x401149: "push 5",
    0x401150: "push 6",
    0x401157: "push 7",
    0x40115E: "push 8",
    0x401165: "push 9",
    0x40116C: "Add",
    0x401177: "Sub",
    0x401182: "Mul",
    0x4011A5: "Div",
    0x4011BE: "Mod",
    0x4011D7: "cmp.zero",
    0x4011E8: "cmp.ge",
    0x4012D9: "dup",
    0x4012DA: "swap",
    0x4012E3: "drop"
}

def dump_regs(uc: Uc):
    regs = [
        ("RAX", UC_X86_REG_RAX),
        ("RBX", UC_X86_REG_RBX),
        ("RCX", UC_X86_REG_RCX),
        ("RDX", UC_X86_REG_RDX),
        ("RSI", UC_X86_REG_RSI),
        ("RDI", UC_X86_REG_RDI),
        ("RBP", UC_X86_REG_RBP),
        ("RSP", UC_X86_REG_RSP),
        ("R8",  UC_X86_REG_R8),
        ("R9",  UC_X86_REG_R9),
        ("R10", UC_X86_REG_R10),
        ("R11", UC_X86_REG_R11),
        ("R12", UC_X86_REG_R12),
        ("R13", UC_X86_REG_R13),
        ("R14", UC_X86_REG_R14),
        ("R15", UC_X86_REG_R15),
        ("RIP", UC_X86_REG_RIP),
        ("EFLAGS", UC_X86_REG_EFLAGS),
    ]
    for name, r in regs:
        val = uc.reg_read(r)
        print(f"{name:6} = 0x{val:016x}")

def stack_sample(uc: Uc, num):       # samples：4 value
    rsp = uc.reg_read(UC_X86_REG_RSP)
    print([uc.mem_read(rsp + 8*i, 8).hex() for i in range(num)])
    print([uc.mem_read(rsp + 8*i, 1) for i in range(num)])


def hook_code(mu : Uc, address, size, user_data):  
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

    global global_counter
    code = mu.mem_read(address, size)

    # 2) Disassemble a single instruction
    for insn in md.disasm(bytes(code), address, count=1):
        # Print disassembled instruction (optional)
        # print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

        # 3) Check if it is "syscall"
        if insn.mnemonic == "syscall":
            # Read registers from Unicorn to identify syscall
            rax = mu.reg_read(UC_X86_REG_RAX)
            rdi = mu.reg_read(UC_X86_REG_RDI)
            rsi = mu.reg_read(UC_X86_REG_RSI)
            rdx = mu.reg_read(UC_X86_REG_RDX)

            if rax == SYS_READ:
                # skip this instr
                # and simu the stdin
                buf = rsi
                len = rdx
                c_byte = fake_stdin.getc()
                print('get: ')
                print(c_byte.decode())
                print('')
                mu.reg_write(UC_X86_REG_RIP, address + size)
                mu.mem_write(buf, c_byte)
            elif rax == SYS_WRITE:
                buf = rsi
                len = rdx
                data = mu.mem_read(buf, len)
                mu.reg_write(UC_X86_REG_RIP, address + size)
                print('===== STDOUT =====')
                print(data.decode())
                print('==================')
            else:
                print(f'unexpected syscall:{rax}')
                exit(-1)
        elif insn.mnemonic == "call":       # call指令，过滤特定函数
            print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}  <-- CALL")

            addr_value = None
            
                
            if insn.operands != None:
                op = insn.operands[0]
                if op.type == CS_OP_IMM:
                    addr_value = op.imm
            
            if addr_value:
                # func_label = func_map.get(addr_value, '<-->')
                # print('##', func_label, end='')
                # stack_sample(mu, 4)
                # print('--------------------------------')
                if addr_value in func_map.keys():
                    func_label = func_map[addr_value]
                    print('###', func_label, end='')
                    stack_sample(mu, 4)
                    print('--------------------------------')
                        
                    
                
                
            
                
            
            
        # elif insn.mnemonic == "ret":
        #     rsp = mu.reg_read(UC_X86_REG_RSP)
        #     ret_addr =  int.from_bytes(mu.mem_read(rsp, 8)) # get the ret addr
        #     
        #     func_label = func_map.get(ret_addr, '<-->') # normal function
        #     print('###', func_label)
                
            


        break  # we only disassembled 1 instruction
    # dump_regs(mu)
    # rsp_val = mu.reg_read(UC_X86_REG_RSP)
    # instr_bytes = mu.mem_read(address, size)
    # print(f'instr {instr_bytes.hex()}')
    #
    # if rsp_val < STACK_SIZE - 40:
    #     print(f'{hex(rsp_val)} Stack: {[mu.mem_read(rsp_val + 8*i, 8) for i in range(5)]}')
    # print('')

mu.hook_add(UC_HOOK_CODE, hook_code)

# 启动
mu.emu_start(0x4013E1, 0x401B89)
```

### 0x06 感想
unicorn的hook_code功能能够完成很多和代码特征强相关的逻辑，相比ida脚本和gdb脚本，减弱了“中断调试”功能，但是dump数值的能力更强，而且也能够对代码的执行逻辑进行微小的修改（比如通过修改`RIP`来改变控制流）。

所谓“动态分析”，很多时候要靠寄存器/栈上的数据来猜想其逻辑，这也是它相较于静态方法的优点。
在面对一个未知的程序时，尝试dump出有用的数据，对于作用不大的数据，如果一味地不舍得扔掉，反而可能影响分析的效率。

在分析程序的时候，编写自己的工具，泄露那些最能反映程序执行流程的信息，在这一个挑战中，是算数类型的gadget函数，和栈上的值。
