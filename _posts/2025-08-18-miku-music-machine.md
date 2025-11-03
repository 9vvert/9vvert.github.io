---
title: Miku Music Machine 
categories: [ctf2025, sekaiCTF]
tags: [reverse, xfg-protect, maze]
---

### 0x1 xfg防护
程序内容非常直白，输入50个字符，每个字符与固定数据异或后获得的字节分成4部分，每组 2bit， 进行四选一的操作，最后要求 v8 等于特定值。从这里其实感觉有点像迷宫问题，只是有点奇怪，怎么没有别的限制？
```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 prompt_len; // rax
  __int64 index; // rbp
  const char *v7; // rcx
  int v8; // edi
  __int64 func_ptr; // rbx
  __int64 v10; // r14
  unsigned __int8 v11; // si
  HMIDIOUT phmo; // [rsp+70h] [rbp+18h] BYREF

  if ( argc < 2 )
  {
    puts("Usage: %s <prompt>\n");
    return 1;
  }
  prompt_len = -1i64;
  do
    ++prompt_len;
  while ( argv[1][prompt_len] );
  if ( prompt_len != 50 )                       // len = 50
  {
    puts("You should work on the length of your prompt!\n");
    return 1;
  }
  index = 0i64;
  if ( midiOutOpen(&phmo, 0, 0i64, 0i64, 0) )
  {
    v7 = "Failed to open MIDI device.\n";
  }
  else
  {
    v8 = 22;
    func_ptr = 22i64;
    do
    {
      v10 = 4i64;
      v11 = data_140073000[index] ^ argv[1][index];
      do
      {
        if ( (v11 & 3) != 0 )
        {
          switch ( v11 & 3 )
          {
            case 1:                            
              ++v8;
              ++func_ptr;
              break;
            case 2:                            
              v8 += 21;
              func_ptr += 21i64;
              break;
            case 3:                            
              --v8;
              --func_ptr;
              break;
          }
        }
        else                                    
        {
          v8 -= 21;
          func_ptr -= 21i64;
        }
        func_table[func_ptr]();
        midiOutShortMsg(phmo, dwMsg);
        Sleep(0x1Eu);
        v11 >>= 2;
        --v10;
      }
      while ( v10 );
      ++index;
    }
    while ( index < 50 );
    Sleep(0x3E8u);
    midiOutReset(phmo);
    midiOutClose(phmo);
    if ( v8 == 418 )
    {
      puts("That was beautiful!\n");
      return 0;
    }
    v7 = "I think you should work on your music.\n";
  }
  puts(v7);
  return 1;
}
```
注意到每轮之后还会调用一个函数，根据当前所在的位置来获得函数表中的一项。跟踪进去后，发现似乎没有什么有用的逻辑：
```c++
char sub_7FF7875B25F0()
{
  dwMsg = 4083600;
  return 41;
}
```
其它位置所有的函数都是这样的结构，只是dwMsg的值不同。

真正运行之后，随便输入了一个字符串，发现程序竟然卡了一会儿，然后异常退出了。

起初怀疑是dwMsg传入的数据可能超过了有效的范围，去搜索相关的结构定义，但是并没有发现什么异常。然而当切换到汇编视角的时候，发现了一些奇怪的东西：
```c++
func_table[func_ptr]();
midiOutShortMsg(phmo, dwMsg);
```
```asm
.text:00007FF7875B4896                 mov     rax, rva func_table[r12+rbx*8]
.text:00007FF7875B489E                 call    cs:__guard_xfg_dispatch_icall_fptr
.text:00007FF7875B48A4                 mov     edx, cs:dwMsg   ; dwMsg
.text:00007FF7875B48AA                 mov     rcx, [rsp+58h+phmo] ; hmo
.text:00007FF7875B48AF                 call    cs:__imp_midiOutShortMsg
```
在调用函数表中的项目时，穿插了一个奇怪的__guard_xfg_dispatch_icall_fptr函数，动态调试后发现，这正是程序异常退出的罪魁祸首！

其中该函数的起始部分如下：
```asm
ntdll.dll:00007FFD25A07040
ntdll.dll:00007FFD25A07040 loc_7FFD25A07040:                       ; CODE XREF: main+10E↑p
ntdll.dll:00007FFD25A07040                                         ; sub_7FF75ACB4A6C+2C↑p ...
ntdll.dll:00007FFD25A07040                 mov     r11, 7DF5765D0000h
ntdll.dll:00007FFD25A0704A                 mov     r10, rax
ntdll.dll:00007FFD25A0704D                 shr     r10, 9
ntdll.dll:00007FFD25A07051                 mov     r11, [r11+r10*8]
ntdll.dll:00007FFD25A07055                 mov     r10, rax
ntdll.dll:00007FFD25A07058                 shr     r10, 3
ntdll.dll:00007FFD25A0705C                 test    al, 0Fh
ntdll.dll:00007FFD25A0705E                 jnz     short loc_7FFD25A07069
ntdll.dll:00007FFD25A07060                 bt      r11, r10
ntdll.dll:00007FFD25A07064                 jnb     short loc_7FFD25A07074
ntdll.dll:00007FFD25A07066                 jmp     rax
......
; 后面有很多分支
```
经过测试，正常的函数会执行 jmp rax的逻辑，而异常的函数会持续执行，直到报错、退出。
查阅相关资料，cfg防护技术是为了防止控制流劫持而研发出的防护技术，在编译/链接时，编译器会收集所有合法的函数入口点，运行时调用间接函数前，会通过一个检查函数验证目标地址是否合法。而xfg技术是cfg的升级版，还引入了函数签名校验机制。

在调试的时候，发现会使用到内存中一个特定区域中的数据，非法函数在判断失败后跳转到后面的逻辑。但是试图查看这些数据的时候, ida中一直显示 `????????`，即使用admin运行ida也看不见。或许这种防护技术就是不让轻易读取这些数据吧。

### 0x2 爆破有效函数，尽显基米精神
一时半会儿没找到太多关于这个技术的资料，但是我突然想到，或许可以利用脚本自动爆破？调用非法函数crash的返回值是一个特定的值，反正不是0或者1.

但是接下来还有一个问题：编写脚本需要自己能够随控制调用哪个函数，怎么办呢？程序和外部之间进行信息交换，最容易的似乎就是命令行，而这一题刚好会读取命令行的字符串参数，而且还有验证长度的逻辑。我有一个大胆的想法：可以删除无用逻辑，使得字符串的长度作为函数指针：
```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v4; // rcx
  __int64 v5; // rax
  HMIDIOUT hmo; // [rsp+70h] [rbp+18h]

  if ( argc >= 2 )
  {
    v4 = argv[1];
    v5 = -1i64;
    do
      ++v5;
    while ( v4[v5] );
    ((void (__fastcall *)(const char *, const char **, const char **))off_7FF78D243040[v5])(v4, argv, envp);
    Sleep(0x3E8u);
    midiOutReset(hmo);
    midiOutClose(hmo);
    sub_7FF78D1D4950("I think you should work on your music.\n");
    return 1;
  }
  else
  {
    sub_7FF78D1D4950("Usage: %s <prompt>\n", *argv);
    return 1;
  }
}
```
（不得不说ida的patch插件是真好用……）

然后编写脚本：
```python
import subprocess
import re
program = "./miku-music-machine.exe"

validate_table = []
for i in range(1,441):    # 0号已经验证过了，是非法函数。这里从1开始
    arg = 'a'*i
    result = subprocess.run([program, arg], capture_output=True, text=True)
    match = re.search(r"returncode=(\d+)", str(result))
    return_code = int(match.group(1))
    print('Testing ',i, 'return ', return_code)
    if return_code==1:
        validate_table.append(i)

with open('./validFunc.txt','w') as f:
    for validate_index in validate_table:
        f.writelines(str(validate_index)+'\n')
```
python的subprocess能够开启新的进程，可以指定命令行、检测返回信息。经过patch后，正常函数都会return 1

大约跑了一个多小时，终于跑完了。基米！

### 0x3 迷宫寻路
```python
validPos = []
with open('./validateFunc.txt', 'r') as f:
    lines = f.readlines()
for line in lines:
    validPos.append(int(line))
for i in range(21):
    for j in range(21):
        pos = 21*i+j
        if pos in validPos:
            print('.',end='')
        else:
            print('#',end='')
    print('')
```
顺带一提，这一题比赛的时候先后给了2个exe，主办方说原始的附件解出来的一些路径可能会被程序接受，但是不是正确的flag，然而是当我使用第二个“修正版”的时候，解出来的迷宫是死路，于是又回去使用原始exe，埋下伏笔(

```
#####################
#@#...#.............#
#.###.#######.#.#.#.#
#.........#...#.#.#.#
###.#####.###.#.#####
#...#.#.#.....#.....#
#####.#.#####.###.###
#...............#...#
#.#########.#######.#
#.#.#.#.......#.#.#.#
###.#.#.#.###.#.#.#.#
#.#.....#...#.#.....#
#.#####.#######.###.#
#.............#.#...#
#.###.#.#.#.#.#.#.#.#
#.#...#.#.#.#.#.#.#.#
###.#.###.###.#.###.#
#...#.#.....#.#...#.#
#.#.#.###.#####.#.#.#
#.#.#...#...#...#.#*#
#####################
```
通过验证`SEKAI{`这几个字符，确实在走正确的路。然而从起点到终点的最短距离明显比200步要短，这意味着中间一定会走一些“无用”的路径。

尝试编写一个寻路脚本：
```python
import copy
import os
validPos = []
with open('./validateFunc.txt', 'r') as f:
    lines = f.readlines()
for line in lines:
    validPos.append(int(line))

data = [0x09,0x40,0x11,0xE4,0x1C,0x81,0x92,0xDB,0x0B,0x75,0x26,0x6A,0x2F,0x7F,0xDD,0xD2,0x52,0x21,0x76,0x9F,\
0xDF,0x8E,0x8F,0xCD,0x9F,0x84,0x61,0x3F,0x6D,0x7A,0x87,0x1E,0x21,0x99,0xC7,0x65,0xDC,0xC8,0x4A,0x22,\
0x7D,0x28,0x64,0x69,0xDC,0x20,0x34,0xED,0xFB,0xD7]

def convert(m):
    if m == 0:
        return '^'
    elif m == 1:
        return '>'
    elif m == 2:
        return 'V'
    elif m == 3:
        return '<'
    else:
        return '?'
    
def checkMove(tmpPos, m_list):
    for m in m_list:
        if m =='^':
            tmpPos -= 21
        elif m =='>':
            tmpPos += 1
        elif m =='V':
            tmpPos += 21
        elif m =='<':
            tmpPos -= 1
        if tmpPos not in validPos:
            return 0
    return tmpPos

def tryToMove(tmpPos, currentStr):
    c = data[len(currentStr)]
    pos_list = []
    str_list = []
    for d in range(32, 127):
        x = c^d
        m1, m2, m3, m4 = convert(x&3), convert((x>>2)&3), convert((x>>4)&3), convert((x>>6)&3)
        result = checkMove(tmpPos, [m1, m2, m3, m4])
        if result!=0 :
            pos_list.append(result)
            str_list.append(currentStr+chr(d))
    return copy.deepcopy(pos_list), copy.deepcopy(str_list)

def simuMove(tmpPos, tmpStr):
    for i in range(len(tmpStr)):
        d = data[i]
        c = ord(tmpStr[i])
        x = c^d
        m1, m2, m3, m4 = convert(x&3), convert((x>>2)&3), convert((x>>4)&3), convert((x>>6)&3)
        for m in [m1, m2, m3, m4]:
            if m =='^':
                tmpPos -= 21
            elif m =='>':
                tmpPos += 1
            elif m =='V':
                tmpPos += 21
            elif m =='<':
                tmpPos -= 1
    return tmpPos


str_list = ['SEKAI{']
pos_list = []
pos_list.append(simuMove(22, str_list[0]))

for i in range(len(str_list[0]), 50):
    print(i)
    x,y, a,b = [],[],[],[]
    for i in range(len(pos_list)):
        a, b = tryToMove(pos_list[i], str_list[i])
        x.extend(a)
        y.extend(b)
    pos_list = x
    str_list = y
    print('---------------------------')
    print(i)
    print('---------------------------')
    print(str_list)

for flag in str_list:
    print(flag)    
```
运行后发现没几步就算不动了，调试一下发现，存在以下问题：
+ 每次返回的 pos_list中有很多重复的位置，应该增加一个purify函数删去。如果最后出现多解，只需要根据pos_list中的路线再重新枚举所有可能，会大大节省运算时间
+ 包含很多flag中不太可能出现的字符，尝试增加一个charset限制
+ 已经确定的`SEKAI{`部分每一个字母对应的四步移动中，都是“成对进行”的，也就是说前两步、后两步的移动是一样的，答案很可能是这种形式，如果不加限制，可能会出现`><<<`，`><><`这样的移动

新版：
```python
import copy
import os
validPos = []
with open('./validateFunc.txt', 'r') as f:
    lines = f.readlines()
for line in lines:
    validPos.append(int(line))

data = [0x09,0x40,0x11,0xE4,0x1C,0x81,0x92,0xDB,0x0B,0x75,0x26,0x6A,0x2F,0x7F,0xDD,0xD2,0x52,0x21,0x76,0x9F,\
0xDF,0x8E,0x8F,0xCD,0x9F,0x84,0x61,0x3F,0x6D,0x7A,0x87,0x1E,0x21,0x99,0xC7,0x65,0xDC,0xC8,0x4A,0x22,\
0x7D,0x28,0x64,0x69,0xDC,0x20,0x34,0xED,0xFB,0xD7]

charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_}'

def convert(m):
    if m == 0:
        return '^'
    elif m == 1:
        return '>'
    elif m == 2:
        return 'V'
    elif m == 3:
        return '<'
    else:
        return '?'
    
def checkMove(tmpPos, m_list):
    for m in m_list:
        if m =='^':
            tmpPos -= 21
        elif m =='>':
            tmpPos += 1
        elif m =='V':
            tmpPos += 21
        elif m =='<':
            tmpPos -= 1
        if tmpPos not in validPos:
            return 0
    return tmpPos

def tryToMove(tmpPos, currentStr):
    c = data[len(currentStr)]
    pos_list = []
    str_list = []
    for d in range(32, 127):
        if chr(d) in charset:
            x = c^d
            m1, m2, m3, m4 = convert(x&3), convert((x>>2)&3), convert((x>>4)&3), convert((x>>6)&3)
            # if m1==m2 and m3==m4:
            result = checkMove(tmpPos, [m1, m2, m3, m4])
            if result!=0 :
                pos_list.append(result)
                str_list.append(currentStr+chr(d))
    return copy.deepcopy(pos_list), copy.deepcopy(str_list)

def simuMove(tmpPos, tmpStr):
    for i in range(len(tmpStr)):
        d = data[i]
        c = ord(tmpStr[i])
        x = c^d
        m1, m2, m3, m4 = convert(x&3), convert((x>>2)&3), convert((x>>4)&3), convert((x>>6)&3)
        for m in [m1, m2, m3, m4]:
            if m =='^':
                tmpPos -= 21
            elif m =='>':
                tmpPos += 1
            elif m =='V':
                tmpPos += 21
            elif m =='<':
                tmpPos -= 1
    return tmpPos

def purify(str_list, pos_list):
    have_occer = []
    new_str_list, new_pos_list = [],[]
    for i in range(len(pos_list)):
        if pos_list[i] not in have_occer:
            have_occer.append(pos_list[i])
            new_str_list.append(str_list[i])
            new_pos_list.append(pos_list[i])
        else:
            continue
    return copy.deepcopy(new_str_list), copy.deepcopy(new_pos_list)

str_list = ['SEKAI{']
pos_list = []
pos_list.append(simuMove(22, str_list[0]))

for i in range(len(str_list[0]), 50):
    x,y, a,b = [],[],[],[]
    for j in range(len(pos_list)):
        a, b = tryToMove(pos_list[j], str_list[j])
        x.extend(a)
        y.extend(b)
    pos_list = x
    str_list = y
    print('---------------------------')
    print(i)
    print('---------------------------')
    str_list, pos_list = purify(str_list, pos_list)
    # print(str_list)
    print(pos_list)
 
for i in range(len(pos_list)):
    if pos_list[i] == 418:
        print(str_list[i]) 
```
最后跑出来：
```
SEKAI{0SSRQ5PPWZZSQ0PQR8BQ607PP1S3EeY0OrxUaiyznGQ}
```
然而输进去，说不是正确的flag

### 0x4 正确解法
赛后看discord里大佬的解法，发现自己的方法是错误的。原来那个“死路”的迷宫是题目的本意，只不过存在一些开关函数，自己没有发现。当通过特定的地点后，就能够打开这些门。

比如开关函数：
```asm
.text:00007FF78D1D4430 ; void sub_7FF78D1D4430()
.text:00007FF78D1D4430 sub_7FF78D1D4430 proc near              ; DATA XREF: .rdata:00007FF78D23077E↓o
.text:00007FF78D1D4430                                         ; .data:00007FF78D243110↓o
.text:00007FF78D1D4430                 push    rbp
.text:00007FF78D1D4431                 mov     rbp, rsp
.text:00007FF78D1D4434                 mov     cs:dword_7FF78D243034, 5E0E90h
.text:00007FF78D1D443E                 xor     byte ptr cs:loc_7FF78D1D179E, 7Dh
.text:00007FF78D1D4445                 pop     rbp
.text:00007FF78D1D4446                 retn
.text:00007FF78D1D4446 sub_7FF78D1D4430 endp
```

附上大佬的解法：
```python
import pefile, struct

pe = pefile.PE('mmm-v2.exe')

for section in pe.sections:
    if section.Name.startswith(b'.text'):
        TEXT = section.get_data()
        TEXT_VA = section.VirtualAddress
    if section.Name.startswith(b'.rdata'):
        RDATA = section.get_data()
        RDATA_VA = section.VirtualAddress
    if section.Name.startswith(b'.data'):
        DATA = section.get_data()
        DATA_VA = section.VirtualAddress

func_table = list(x[0] for x in struct.iter_unpack("<Q", DATA[0x40:0x40+441*8]))
assert(len(func_table) == len(set(func_table))) # check unique

# control flow guard table (used to init bitmap, first check)
fids_table_size = 0x123
fids_table = set(0x140000000 + x[0] for x in struct.iter_unpack("<IB", RDATA[0x3C8:0x3C8+fids_table_size*5]))

# filter func list and build list of 'patchers'
patchable = {}
patchers = []
valid_func_table = func_table[:]
for i in range(len(func_table)):
    addr = func_table[i]
    if addr not in fids_table:
        valid_func_table[i] = 0
        continue
    text_off = addr - TEXT_VA - 0x140000000
    hash = struct.unpack("<Q", TEXT[text_off-8:text_off])[0]
    assert hash == 0x85F13E9656DA4871 # they are modified by relocs i guess..
    special_insn_byte = TEXT[text_off+14]
    if special_insn_byte == 0x80:
        # xor
        relt = struct.unpack("<i", TEXT[text_off+16:text_off+20])[0]
        taddr = relt + addr + 14 + 7
        #print(f"Func {hex(addr)} patches {hex(taddr)}")
        patchers.append((addr, taddr))
    elif special_insn_byte == 0xCD:
        assert TEXT[text_off+15] == 0x29
        #print(f"Func {hex(addr)} has 'int 29h'")
        patchable[addr + 14] = addr
    elif special_insn_byte != 0xB0:
        print(f"Func {hex(addr)} as something else than nops: {hex(TEXT[text_off+14])}")
    
patchers = {a: patchable[b] for a, b in patchers}
#print(patchers)

music_data = DATA[:50]
assert music_data[0] == 0x09

MOVES = (-21, 1, 21, -1)

# let's play

import readchar
import colorama

colorama.init()

# MOVES = (-21, 1, 21, -1) -> UP RIGHT DOWN LEFT

buttons = {x: i for i, x in enumerate(patchers.keys())}
doors = {x: i for i, x in enumerate(patchers.values())}
open_doors = set()

door_colors = [
    (colorama.Back.RED, colorama.Fore.RED),
    (colorama.Back.GREEN, colorama.Fore.GREEN),
    (colorama.Back.BLUE, colorama.Fore.BLUE),
    (colorama.Back.MAGENTA, colorama.Fore.MAGENTA),
    (colorama.Back.CYAN, colorama.Fore.CYAN),
    (colorama.Back.YELLOW, colorama.Fore.YELLOW),
]

accumulated_flag = bytearray()
recorded_moves = []
my_pos = 22
while my_pos != 418:
    for i in range(21):
        line = ""
        for j in range(21):
            lidx = i * 21 + j
            faddr = valid_func_table[i * 21 + j]
            if lidx == my_pos:
                line += '🚶'
            elif lidx == 418:
                line += '🚪'
            elif faddr:
                if faddr in buttons:
                    line += door_colors[buttons[faddr]][1] + f'*{buttons[faddr]}' + colorama.Style.RESET_ALL
                elif faddr in doors:
                    id = doors[faddr]
                    if faddr in open_doors:
                        line += door_colors[id][1] + f'{id}{id}' + colorama.Style.RESET_ALL
                    else:
                        line += door_colors[id][0] + colorama.Fore.BLACK + f'{id}{id}' + colorama.Style.RESET_ALL
                else:
                    line += '  '
            else:
                line += '██'
        print(line)
    
    print(accumulated_flag.decode(errors='replace')) 
    #print(open_doors)
    
    c = readchar.readchar()
    #print(c.encode())

    # escape?
    if c == 'a':
        break

    move = 0
    if c == 'K':
        move = -1
    elif c == 'P':
        move = 21
    elif c == 'M':
        move = 1
    elif c == 'H':
        move = -21
    
    if move != 0:
        my_new_pos = my_pos + move
        faddr = valid_func_table[my_new_pos]
        if faddr:
            if faddr not in doors or faddr in open_doors:
                # move is allowed
                if faddr in buttons:
                    open_doors.add(patchers[faddr])
                my_pos = my_new_pos
                recorded_moves.append(MOVES.index(move))

    # append character every 4 moves
    if len(recorded_moves) == 4:
        a, b, c, d = recorded_moves
        faddr = a | (b << 2) | (c << 4) | (d << 6)
        faddr ^= music_data[len(accumulated_flag)]
        accumulated_flag.append(faddr)
        recorded_moves.clear()
```
这个脚本在熟悉防护原理的基础上，读取文件中的有效函数表来解决。

另外还有大佬用binary ninja的api完成：
```python
from binaryninja import *
from binaryninja.binaryview import BinaryView
from collections import deque

def u64(data: bytes) -> int:
    if len(data) > 8:
        data = data[:8]
    elif len(data) < 8:
        data = data.ljust(8, b'\x00')
    return int.from_bytes(data, byteorder='little', signed=False)

bv: BinaryView = eval('bv')
start = bv.start + 0x73040 # start of function ptr grid

grid = []
gates = {}
for i in range(21):
    row = []
    for j in range(21):
        ptr = u64(bv.read(start + (i * 21 * 8) + (j * 8), 8))
        func = bv.get_function_at(ptr)
        
        if func is None:
            # Not a valid function in CFG bitmap
            # Thus Binja will not autogenerate the function symbol
            # So if there is no function there, we cannot go there
            row.append('#')
            continue

        disas = list(list(map(str, inst)) for inst, addr in func.instructions)

        if len(disas) == 11: 
            # normal
            row.append('.')
            continue

        if len(disas) == 4:
            # trap -> gate
            if ptr not in gates:
                c = chr(0x41 + len(gates))
                gates[ptr] = (c, [])
            row.append(gates[ptr][0])

        elif len(disas) == 6:
            # toggle for gate
            xor = [line for line in disas if 'xor' in line[0]][0][6]
            target = bv.get_functions_containing(int(xor, 16))[0]
            if target.lowest_address not in gates:
                c = chr(0x41 + len(gates))
                gates[target.lowest_address] = (c, [hex(ptr)])
            else:
                gates[target.lowest_address][1].append(hex(ptr))

            row.append(gates[target.lowest_address][0].lower())
    grid.append(row)

for row in grid:
    print(''.join(row))


# BFS to get path, <= 2^6 * 361 states
H, W = len(grid), len(grid[0])
switch_index = {c: i for i, c in enumerate("abcdef")}
gate_index   = {c: i for i, c in enumerate("ABCDEF")}
start = (1, 1)
goal  = (19, 19)

dxy = [(-1,0,'U'), (1,0,'D'), (0,-1,'L'), (0,1,'R')]
def neighbors(x, y):
    for dx, dy, move in dxy:
        nx, ny = x+dx, y+dy
        if 0 <= nx < H and 0 <= ny < W:
            yield nx, ny, move

def bfs():
    q = deque()
    start_state = (*start, 0)  # x, y, bitmask
    q.append(start_state)
    visited = {start_state: (None, None)}  # state -> (parent, move)

    while q:
        x, y, mask = q.popleft()
        if (x, y) == goal:
            # reconstruct path
            moves = []
            s = (x, y, mask)
            while visited[s][0] is not None:
                parent, move = visited[s]
                moves.append(move)
                s = parent
            return ''.join(reversed(moves))

        for nx, ny, move in neighbors(x, y):
            cell = grid[nx][ny]
            if cell == "#":  # wall
                continue

            new_mask = mask
            if cell in switch_index:  # toggle switch
                bit = switch_index[cell]
                new_mask ^= (1 << bit)
            elif cell in gate_index:  # gate check
                bit = gate_index[cell]
                if not (mask & (1 << bit)):
                    continue

            new_state = (nx, ny, new_mask)
            if new_state not in visited:
                visited[new_state] = ((x, y, mask), move)
                q.append(new_state)

    return None

path = bfs()
print(path)
assert len(path) == 200 # We have 50 chars -> 4 moves per char = 200 moves

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

key = b'\t@\x11\xe4\x1c\x81\x92\xdb\x0bu&j/\x7f\xdd\xd2R!v\x9f\xdf\x8e\x8f\xcd\x9f\x84a?mz\x87\x1e!\x99\xc7e\xdc\xc8J\"}(di\xdc 4\xed\xfb\xd7'

moves = {
    'U': 0,
    'R': 1,
    'D': 2,
    'L': 3
}
inv_moves = {v: k for k, v in moves.items()}

def out_from_moves(wanted):
    assert len(wanted) % 4 == 0, "Length of wanted moves must be a multiple of 4"

    dec = []
    for i in range(0, len(wanted), 4):
        b = 0
        for j, c in enumerate(wanted[i:i+4]):
            b |= moves[c] << (j * 2)
        dec.append(b)

    dec = bytes(dec)
    out = xor(dec, key)
    return out

print(out_from_moves(path).decode())
```
