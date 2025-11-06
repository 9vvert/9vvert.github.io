---
title: n1CTF - True Operator Master
categories: [ctf2025, n1CTF]
tags: [reverse, junk-code, script, control-flow-flattening, constraint-solving]
toc: false
---

### 0x01 初步分析：控制流混淆，花指令，运算符重载

UPX去壳后，很容易定位核心函数所在的位置。其中`sub_7FF70E1FD3E8`和`sub_7FF70E1FD4B5`都是字节序变换的函数，真正棘手的是for循环中的`sub_7FF70E1FD5AC`，会执行6轮，每次使用8字节进行变换（后续称呼为fuck函数）
```c++
// bad sp value at call has been detected, the output may be wrong!
// positive sp value has been detected, the output may be wrong!
void sub_7FF70E22EDD7()
{
  int v0; // [rsp+28h] [rbp-C8h] BYREF
  int v1; // [rsp+2Ch] [rbp-C4h]
  _DWORD v2[4]; // [rsp+30h] [rbp-C0h] BYREF
  _DWORD v3[12]; // [rsp+40h] [rbp-B0h] BYREF
  char v4[64]; // [rsp+70h] [rbp-80h] BYREF
  char Str[56]; // [rsp+B0h] [rbp-40h] BYREF
  int j; // [rsp+E8h] [rbp-8h]
  int i; // [rsp+ECh] [rbp-4h]

  sub_7FF70E22F040();
  puts("Input your flag: ");
  v2[0] = -1263316434;
  v2[1] = 601749298;
  v2[2] = 348273441;
  v2[3] = -202134348;
  sub_7FF70E2300C0("%48s", Str);
  if ( strlen(Str) != 48 )
  {
    puts("Wrong length!");
    ((void (__fastcall *)(_QWORD))sub_7FF70E22FC40)(0);
  }
  ((void (__fastcall *)(char *, _DWORD *, __int64))sub_7FF70E1FD3E8)(Str, v3, 48);
  for ( i = 0; i <= 11; i += 2 )
  {
    v0 = v3[i];
    v1 = v3[i + 1];
    ((void (__fastcall *)(int *, _DWORD *))sub_7FF70E1FD5AC)(&v0, v2);
    v3[i] = v0;
    v3[i + 1] = v1;
  }
  ((void (__fastcall *)(_DWORD *, char *, __int64))sub_7FF70E1FD4B5)(v3, v4, 48);
  for ( j = 0; j <= 47; ++j )
  {
    if ( v4[j] != byte_7FF70E231000[j] )
    {
      puts("Wrong flag!");
      ((void (__fastcall *)(_QWORD))sub_7FF70E22FC40)(0);
    }
  }
  puts("Right flag!");
  ((void (__fastcall *)(_QWORD))sub_7FF70E22FC40)(0);
  JUMPOUT(0x7FF70E22EF74LL);
}
```

fuck函数过大，甚至无法在ida中反编译。入口处有一系列初始化函数。除了存放参数的`[rbp+160h+arg_0]`和`[rbp+160h+arg_8]`， 剩下的寄存器有`[rbp+160h+var4/var8/varC/.../var24]`
```c++
.text:00007FF70E1FD5AC 000 55                      push    rbp
.text:00007FF70E1FD5AD 008 48 81 EC E0 01 00 00    sub     rsp, 1E0h
.text:00007FF70E1FD5B4 1E8 48 8D AC 24 80 00 00 00 lea     rbp, [rsp+80h]
.text:00007FF70E1FD5BC 1E8 48 89 8D 70 01 00 00    mov     [rbp+160h+arg_0], rcx
.text:00007FF70E1FD5C3 1E8 48 89 95 78 01 00 00    mov     [rbp+160h+arg_8], rdx
.text:00007FF70E1FD5CA 1E8 48 8B 85 70 01 00 00    mov     rax, [rbp+160h+arg_0]
.text:00007FF70E1FD5D1 1E8 8B 00                   mov     eax, [rax]
.text:00007FF70E1FD5D3 1E8 89 85 5C 01 00 00       mov     [rbp+160h+var_4], eax
.text:00007FF70E1FD5D9 1E8 48 8B 85 70 01 00 00    mov     rax, [rbp+160h+arg_0]
.text:00007FF70E1FD5E0 1E8 8B 40 04                mov     eax, [rax+4]
.text:00007FF70E1FD5E3 1E8 89 85 58 01 00 00       mov     [rbp+160h+var_8], eax
.text:00007FF70E1FD5E9 1E8 C7 85 54 01 00 00 79 56 mov     [rbp+160h+var_C], 12345679h
.text:00007FF70E1FD5E9 1E8 34 12
.text:00007FF70E1FD5F3 1E8 C7 85 50 01 00 00 00 00 mov     [rbp+160h+var_10], 0
.text:00007FF70E1FD5F3 1E8 00 00
.text:00007FF70E1FD5FD 1E8 C7 85 4C 01 00 00 00 00 mov     [rbp+160h+var_14], 0
.text:00007FF70E1FD5FD 1E8 00 00
.text:00007FF70E1FD607 1E8 C7 85 48 01 00 00 00 00 mov     [rbp+160h+var_18], 0
.text:00007FF70E1FD607 1E8 00 00
.text:00007FF70E1FD611 1E8 C7 85 44 01 00 00 00 00 mov     [rbp+160h+var_1C], 0
.text:00007FF70E1FD611 1E8 00 00
.text:00007FF70E1FD61B 1E8 C7 85 40 01 00 00 00 00 mov     [rbp+160h+var_20], 0
.text:00007FF70E1FD61B 1E8 00 00
.text:00007FF70E1FD625 1E8 C7 85 3C 01 00 00 04 8A mov     [rbp+160h+var_24], 0B6998A04h
.text:00007FF70E1FD625 1E8 99 B6
.text:00007FF70E1FD625
```
再往下看，发现了对`[rbp+160h+var_24]`的大量比较判断：
```
.text:00007FF70E1FD62F                             loc_7FF70E1FD62F:                       ; CODE XREF: sub_7FF70E1FD5AC+317F9↓j
.text:00007FF70E1FD62F 1E8 81 BD 3C 01 00 00 5D DD cmp     [rbp+160h+var_24], 0FFFDDD5Dh
.text:00007FF70E1FD62F 1E8 FD FF
.text:00007FF70E1FD639 1E8 0F 84 3C AC 01 00       jz      loc_7FF70E21827B
.text:00007FF70E1FD639
.text:00007FF70E1FD63F 1E8 81 BD 3C 01 00 00 5D DD cmp     [rbp+160h+var_24], 0FFFDDD5Dh
.text:00007FF70E1FD63F 1E8 FD FF
.text:00007FF70E1FD649 1E8 0F 87 4A 17 03 00       ja      loc_7FF70E22ED99
......
```
特征疑似控制流平坦化的混淆。后续验证发现`[rbp+160h+var_24]`和`[rbp+160h+var_28]`都会用来控制流跳转.

另外还可以发现：
- 下面出现了大量`jmp label+1`形式的花指令，尝试使用脚本去除。
- 程序存在大量表示普通运算逻辑的函数，形如：
```
__int64 __fastcall sub_7FF70E1C1450(__int64 a1, __int64 a2)
{
return a2 | a1;
}
```
其中涵盖的运算符有`+, -, *, |, &, <<, >>, ^`



### 0x02 脚本去花指令
在此之前，为了分析fuck函数，可以先将其汇编指令保持在文件中：
```python
import idaapi
import idautils
import idc

lines = ''
def print_function_disasm(addr):
    global lines
    func = idaapi.get_func(addr)
    if not func:
        return
    print(f"Function at 0x{func.start_ea:X}:")
    for ea in idautils.FuncItems(func.start_ea):
        asm = idc.GetDisasm(ea)
        lines += f"0x{ea:X}: {asm}\n"

my_addr = 0x000000014003D5AC 
print_function_disasm(my_addr)
with open('./special_func.asm', 'w') as f:
    f.write(lines)
```
这样虽然失去了“查看数据和引用”的功能，但是能更方便地使用文本搜索

考虑到所有的花指令都是`jmp label+1`形式，对应`74 01`，可以用脚本重点过滤这两条指令。
```
target_addr_list = []

bin_path = 'C:\\Users\\woc\\Desktop\\n1\\origin\\origin.exe'
dst_path = 'C:\\Users\\woc\\Desktop\\n1\\origin\\remove_junk.exe'

text_start = 0x400
text_end = 0x70400

special_list = [0x40fd8, 0x445eb, 0x4fac1, 0x52fc0, 0x5c2d6, 0x6ba17]
with open(bin_path, 'rb') as f:
    origin_bin = bytearray(f.read()) 
    for i in range(text_start, text_end - 1):
        if i in special_list:
            origin_bin[i] = 0x90
        if origin_bin[i] == 0x74 and origin_bin[i+1] == 0x01 and origin_bin[i-2] != 0x0F \
        and origin_bin[i-1] != 0xE8 and origin_bin[i-1] != 0xE9 and origin_bin[i-8] != 0x81:
            origin_bin[i], origin_bin[i+1], origin_bin[i+2] = 0x90, 0x90, 0x90
    with open(dst_path, 'wb') as g:
        g.write(bytes(origin_bin))
```
核心逻辑是将`74 01`序列填充成nop，然而这样做会导致误伤正常代码（主要是指令的数据随机性干扰），经过实验增加了一些限制。然而最终版本会漏掉6个花指令，因此增加special_list

> [TODO]
有没有其他方法来提高花指令的去除准确率？
1. 是否能借助反汇编引擎
2. 能否用ida的api定位出错点（但感觉应该不行，因为属于干扰后指令反汇编失败的“被动报错”）
3. 能否从另一个层级，从信息含量大的asm文本，用脚本处理，获得花指令地址list ?
{: .prompt-tip }

### 0x03 运算符函数批量重命名
注意到所有的函数进行反编译后都是简单的return表达式，因此尝试直接调用api获得反编译文本，然后根据特征重命名。

> 这里还没有到最后的neat环节，所以重复的运算符没有必要去除，保留着甚至可能会利于分析。当时我正是考虑到这一点，增加了index后缀。后来事实证明这个后缀对ida script debug起了很大作用！
{: .prompt-warn }
```python
import idautils
import idaapi
import ida_hexrays

# 运算符及对应英文名
op_map = {
    '+': 'op_add',
    '-': 'op_sub',
    '*': 'op_mul',
    '<<': 'op_shl',
    '>>': 'op_shr',
    '&': 'op_and',
    '|': 'op_or',
    '^': 'op_xor',
}

# 运算符计数器
op_counter = {v: 1 for v in op_map.values()}

# 检查伪代码中是否包含运算符
def find_operator(pseudocode):
    for op, name in op_map.items():
        # 处理多字符运算符优先（比如<<，>>）
        if op in pseudocode:
            return name
    return None

def main(start_ea, end_ea):
    for func_ea in idautils.Functions(start_ea, end_ea):
        try:
            cfunc = str(ida_hexrays.decompile(func_ea)).split('\n')[2]
            #print('------')
            #print(cfunc)
            if not cfunc:
                continue
            # 获取伪代码文本并合成成一个字符串
            op_name = find_operator(cfunc)
            if op_name:
                idx = op_counter[op_name]
                new_func_name = f"{op_name}_{idx}"
                # 重命名函数
                success = idaapi.set_name(func_ea, new_func_name, idaapi.SN_NOWARN)
                if success:
                    #print(f"Renamed 0x{func_ea:X} to {new_func_name}")
                    op_counter[op_name] += 1
                else:
                    print(f"Failed to rename 0x{func_ea:X}")
        except Exception as e:
            print(f"Error decompiling 0x{func_ea:X}: {e}")

# 示例调用：替换为你的start和end地址

start_ea = 0x140001450
end_ea = 0x14003D3E8

main(start_ea, end_ea)
```

### 0x04 trace
经过函数重命名后，尝试在调用每个函数的时候，打印其名称，然后开展进一步的分析。

因为运算符函数是地址连续的，可以很容易用脚本打断点，然后在执行到特定函数的时候，打印函数的名称（而且还可以增加判断：位于这个范围的函数停下来后，自动发送continue指令。这样可以在其它地方正常下断点，但又不会在这里卡住）
```python
import idautils
import idaapi
import ida_dbg

# 设置你要遍历的范围
start_ea = 0x7FF74CC91450
end_ea = 0x7FF74CCCD3E8

# 用于记录函数地址到名字的映射
func_map = {}
target_breakpoints = set()  # 存储我们关心的断点地址

# 收集范围内所有函数
for func_ea in idautils.Functions(start_ea, end_ea):
    target_breakpoints.add(func_ea)
    name = idaapi.get_func_name(func_ea)
    func_map[func_ea] = name

print(f"已在范围 {hex(start_ea)} - {hex(end_ea)} 找到 {len(target_breakpoints)} 个函数。")
result = []
class MyDebugHook(ida_dbg.DBG_Hooks):
    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)
        
    def dbg_bpt(self, tid, ea):
        if ea in target_breakpoints:
            name = func_map[ea]
            try:
                rcx_val = ida_dbg.get_reg_val("RCX")
                rdx_val = ida_dbg.get_reg_val("RDX")
                print(f"Hit: {name}, RCX={rcx_val:#x}, RDX={rdx_val:#x}")
            except Exception as e:
                print(f"Hit: {name} (0x{ea:X}) - 无法获取寄存器: {e}")     
        ida_dbg.continue_process()
        
        # 对于其他断点，什么都不做，直接返回
        return 0  # 继续执行

# 创建并安装调试钩子
debug_hook = MyDebugHook()
debug_hook.hook()

# 只在目标函数上设置断点
success_count = 0
for func_ea in target_breakpoints:
    if ida_dbg.add_bpt(func_ea):
        success_count += 1
print(f"Successfully set breakpoints: {success_count}")
```
> [TODO]
每次patch后，重新打开一个新的文件并调试后，都需要重新调整这里的start和end. 能否手动设置装载地址，或者用脚本来获得一个样本的运行时基地址，然后用脚本动态计算？
{: .prompt-tip }

> [TODO]
虽然能够通过debug_hook中的条件判断来实现不同断点执行不同的逻辑，但我还是好奇：能否不用全局钩子，而对某些特定的断点设置特定的回调函数？
{: .prompt-tip }

### 0x05 恢复上文 & 整合
得到trace样本：
```
Hit: op_and_139 (0x7FF7E982FAE5), RCX=0x0, RDX=0x7
Hit: op_shr_103 (0x7FF7E98537D8), RCX=0x0, RDX=0xcb497beb
Hit: op_or_483 (0x7FF7E985A2B8), RCX=0x12345679, RDX=0x0
Hit: op_sub_459 (0x7FF7E9859CBF), RCX=0x0, RDX=0x4
Hit: op_mul_19 (0x7FF7E982B088), RCX=0x31327b33, RDX=0x0
Hit: op_shl_26 (0x7FF7E982CB66), RCX=0x31327b33, RDX=0xfffffffc
Hit: op_add_444 (0x7FF7E985AECC), RCX=0x0, RDX=0xf3f3acb4
Hit: op_sub_49 (0x7FF7E9827574), RCX=0x0, RDX=0xb4b3522e
......
```
（每次都是2622行，而重载的运算符函数刚好是2622个，极有可能是线性流程，每个函数执行一次！）

另外通过改变输入的数据，获得多个样本，发现函数执行的顺序不会发送改变（只有部分数据改变）

然而上面的数据，如果想要LLM分析，似乎还是有点困难。核心是因为只保留了寄存器数据，却丢失了上下文的序号信息。

通过观察我们可以发现函数在栈上预留了一些空间，仅有`[rbp+160h+var4/var8/varC/.../var20]`会参与运算符函数的参数/返回值，因此可以将其看作vm 寄存器。能否用某些手动恢复函数调用前、返回的reg编号？

我在比赛期间采用了一个蹩脚的方法：因为我们可以获得函数的asm文本，而这些函数一般是由出题人用程序自动生成的，所以应该有一些规律。尝试找出其中的规律，用机械匹配算法恢复context。

想要定位运算符函数所在的行很容易，然后可以向下读取1或2行获得return reg，但是向上的情况有很多种，如果一行一行向上扩展似乎并不容易界定终止条件。不过可以注意到的是，运算符函数似乎都会在花指令的下方：
```
0x7FF74CCE8E16: nop
0x7FF74CCE8E17: nop
0x7FF74CCE8E18: nop
0x7FF74CCE8E19: mov     edx, [rbp+160h+var_14]
0x7FF74CCE8E1F: mov     eax, [rbp+160h+var_8]
0x7FF74CCE8E25: mov     ecx, eax
0x7FF74CCE8E27: call    op_mul_3
0x7FF74CCE8E2C: mov     [rbp+160h+var_14], eax
0x7FF74CCE8E32: sub     [rbp+160h+var_F8], 275E1DFAh
0x7FF74CCE8E39: jmp     loc_7FF74CCE9123
0x7FF74CCE8E3E: xor     eax, eax
0x7FF74CCE8E40: nop
0x7FF74CCE8E41: nop
0x7FF74CCE8E42: nop
0x7FF74CCE8E43: nop
0x7FF74CCE8E44: nop
0x7FF74CCE8E45: nop
0x7FF74CCE8E46: mov     rax, [rbp+160h+arg_8]
0x7FF74CCE8E4D: add     rax, 0Ch
0x7FF74CCE8E51: mov     edx, [rax]
0x7FF74CCE8E53: mov     eax, [rbp+160h+var_14]
0x7FF74CCE8E59: mov     ecx, eax
0x7FF74CCE8E5B: call    op_and_35
0x7FF74CCE8E60: mov     [rbp+160h+var_14], eax
0x7FF74CCE8E66: mov     eax, [rbp+160h+var_F8]
0x7FF74CCE8E69: mov     edx, eax
0x7FF74CCE8E6B: mov     eax, 0CCCCCCCDh
0x7FF74CCE8E70: imul    rax, rdx
0x7FF74CCE8E74: shr     rax, 20h
0x7FF74CCE8E78: shr     eax, 2
0x7FF74CCE8E7B: mov     [rbp+160h+var_F8], eax
0x7FF74CCE8E7E: jmp     loc_7FF74CCE9123
0x7FF74CCE8E83: xor     eax, eax
```
因此可以在线性扫描，从一个`nop block`出来的时候，开始记录上文指令。只不过程序本身可能包含一些自然nop，我这里设置的条件是`nop block中的nop条数>=3` 。然而这样仍然有遗漏，因为有几条函数调用前的nop不足3个，需要额外添加。

> 另一种方式是：找到op函数后向上读取，直到nop停止。其实这种方法更好，能节省后续的很多麻烦
{: .prompt-info}



```python
from enum import Enum
asm_path = 'C:\\Users\\woc\\Desktop\\n1\\origin\\special_func.asm'

sample_path = 'C:\\Users\\woc\\Desktop\\n1\\origin\\sample.txt'  # trace结果
# nop block
in_scope = False
last_in_scope = False
total = 0
scope_counter = 0

vm_instr = []
def neat_instr(dst, lhs, rhs, op_func):
    op_map = {
        "add": "+",
        "sub": "-",
        "mul": "*",
        "and": "&",
        "or": "|",
        "xor": "^",
        "shl": "<<",
        "shr": ">>"
    }
    if 'shl' in op_func or 'shr' in op_func:
        
        if rhs[0] == 'R':
            rhs += ' & 0xFF'
        # 如果右操作数是数据，直接计算出来
        else:
            if rhs [-1] == 'h':
                rhs = f'({hex(int(rhs[:-1], 16) & 255)})' 
            else:
                rhs = f'({hex(int(rhs) & 255)})'
    op_type= op_func.split('_')[1]
    return f'{dst} = {lhs} {op_map[op_type]} {rhs}'

reg_map = {
    "[rbp+160h+var_4]" : "R1",
    "[rbp+160h+var_8]" : "R2",
    "[rbp+160h+var_C]" : "R3",
    "[rbp+160h+var_10]": "R4",
    "[rbp+160h+var_14]": "R5",
    "[rbp+160h+var_18]": "R6",
    "[rbp+160h+var_1C]": "R7",
    "[rbp+160h+var_20]": "R8"
}
opfunc_map = {}
# call block
class Stat(Enum):
    IDLE=0
    PRE=1
    RET=2
enumerate 
call_block_stat = Stat.IDLE
# pre
pre_lines = []
# in
edx,ecx,tmp_eax = '', '', ''
opcode_func = ''
# after
dst_reg = ''

addition = ['0x7FF74CCD1BD9', '0x7FF74CCD51EC', '0x7FF74CCE06C2', '0x7FF74CCEBBDE', '0x7FF74CCFC618']

with open(asm_path) as f:
    lines = f.readlines()
    for line in lines:
        if 'nop' in line:
            scope_counter += 1
            if not last_in_scope:
                in_scope = True
        else:
            if last_in_scope and scope_counter >= 3 or line.split()[0][:-1] in addition:
                total += 1
                # 从一个nop数量>=3的块出来，开始进行匹配
                call_block_stat = Stat.PRE
                
            if call_block_stat == Stat.PRE:
                if 'call' in line:
                    # 分析pre_lines
                    line_num = len(pre_lines)
                    ptr = 0
                    ecx, edx, tmp_eax = '', '', ''
                    while ptr < line_num:
                        # 情况1：fetch int array (固定2~3行)
                        if 'arg' in pre_lines[ptr]:
                            assert('rax, [rbp+160h+arg_8]' in pre_lines[ptr])
                            # 接下来可能有直接解引用，可能先偏移后引用
                            # 默认无偏移，2行
                            offset = 0
                            line_offset = 0
                            if 'add' in pre_lines[ptr+1]:
                                # 有偏移量，3行
                                line_offset = 1 
                                num_str = pre_lines[ptr+1].strip().split()[3]
                                if num_str[-1] == 'h':
                                    num_str = num_str[:-1]
                                offset = int(num_str, 16)
   
                            assert('[rax]' in pre_lines[ptr+1+line_offset])
                            obj_reg = pre_lines[ptr+1+line_offset].strip().split()[2].strip(',')
                            if obj_reg == 'edx':
                                edx = f'DWORD[a2+{offset}]'
                            elif obj_reg == 'ecx':
                                ecx = f'DWORD[a2+{offset}]'
                            else:
                                print('Invalid object_reg')
                                exit(-1)
                            ptr += (2+line_offset)
                        # 情况2：普通赋值，可能一步到edx/ecx，也可能借助eax中转
                        else:
                            lhs = pre_lines[ptr].strip().split()[2].strip(',')
                            rhs = pre_lines[ptr].strip().split()[3]
                            if lhs == 'ecx':
                                if rhs == 'eax':
                                    assert(tmp_eax != '')
                                    ecx = tmp_eax
                                else:
                                    ecx = rhs
                                
                            elif lhs == 'edx':
                                if rhs == 'eax':
                                    assert(tmp_eax != '')
                                    edx = tmp_eax
                                else:
                                    edx = rhs
                            elif lhs =='eax':
                                tmp_eax = rhs
                            else:
                                print(pre_lines[ptr].split())
                                print(f'Invalid lhs {lhs}')
                                exit(-2)
                            # 
                            ptr += 1
                            

                    # 提取call指令
                    assert('op_' in line)
                    call_block_stat = Stat.RET
                    opcode_func = line.strip().split()[2]
                else:
                    pre_lines.append(line.strip())
            elif call_block_stat == Stat.RET:
                if 'ax' in line:
                    assert(', eax' in line)
                    dst_reg = line.strip().split()[2].strip(',')
                    call_block_stat = Stat.IDLE     # 结束一个call_block的分析
                    # 压入处理的指令
                    # 寄存器替换
                    # 
                    l = []
                    for x in [dst_reg, ecx, edx]:
                        if x in reg_map.keys():
                            x = reg_map[x]
                        l.append(x)
                    # shr/shl的rhs是char类型，这种情况下进行截断后显示
                    

                    curr_str = neat_instr(l[0], l[1], l[2], opcode_func)
                    vm_instr.append(curr_str)    
                    opfunc_map[opcode_func] = curr_str

            scope_counter = 0
            in_scope = False
        last_in_scope = in_scope
# print(total)
# for instr in vm_instr:
#     print(instr)



# 根据sample的顺序恢复
real_trace = []
with open(sample_path) as f:
    lines = f.readlines()
    for line in lines:
        func_name = line.split()[1]
        if func_name != '':
            real_trace.append(opfunc_map[func_name])
for line in real_trace:
    print(line)
```
得到：
```
R5 = R8 & 7
R4 = R8 >> (0xeb)
R3 = R3 | R4
R6 = R8 - 4
R5 = R2 * R5
R6 = R2 << R6 & 0xFF
R5 = R5 + DWORD[a2+12]
R6 = R6 - DWORD[a2+0]
R7 = R2 + R3
R6 = R6 & R7
......
R5 = R1 & R5
R6 = R1 * R6
R5 = R5 | DWORD[a2+4]
R6 = R6 - DWORD[a2+8]
R7 = R1 ^ R3
R6 = R6 + R7
R5 = R5 & R6
R8 = R8 & 1
R2 = R2 ^ R5
```

### 0x07 止步
丢给LLM，完全是胡言乱语。

查看数据结构，发现vm reg中的数据结构有点像tea算法（处理4+4字节，交替处理对应R1和R2，初始会赋值一个4Byte的常量），然而仔细看后发现并不是。


>不太确定其中的哪些指令是处理输入，哪些是执行固定的计算，尝试改变输入的值，然后diff比较两次的trace sample.
结果发现刚开始的时候，两个文件会有部分的区别，但是执行到最后不一样之处越来越少，直到最后返回的结果都一样！调试之后，发现不同的数据处理结果竟然真的是相同的，说明一般的数据会在其中丢失信息，形成“多对一”的结果

```
R5 = R8 & 7
R4 = R8 >> (0xeb)
R3 = R3 | R4
R6 = R8 - 4
R5 = R2 * R5
R6 = R2 << R6 & 0xFF
R5 = R5 + DWORD[a2+12]
R6 = R6 - DWORD[a2+0]
R7 = R2 + R3
R6 = R6 & R7
R5 = R5 & R6
R1 = R1 | R5

R5 = R8 - 5
R6 = R8 << (0x6)
R5 = R1 << R5 & 0xFF
R6 = R1 ^ R6
R5 = R5 | DWORD[a2+4]
R6 = R6 & DWORD[a2+8]
R7 = R1 & R3
R6 = R6 & R7
R5 = R5 - R6
R2 = R2 & R5

R8 = R8 - 1
R6 = R8 >> (0x4)
R4 = R8 ^ 522E687Eh
R5 = R8 & 7
R3 = R3 ^ R4
R5 = R2 | R5
R6 = R2 << R6 & 0xFF
R5 = R5 & DWORD[a2+12]
R6 = R6 - DWORD[a2+0]
R7 = R2 - R3
R6 = R6 + R7
R5 = R5 - R6
R1 = R1 ^ R5

R5 = R8 + 5
R6 = R8 & 6
R5 = R1 << R5 & 0xFF
R6 = R1 | R6
R5 = R5 + DWORD[a2+4]
R6 = R6 | DWORD[a2+8]
R7 = R1 & R3
R6 = R6 | R7
R5 = R5 & R6
R2 = R2 | R5
......

```


我发现似乎可以划分其中的一些块结构，这样可以划分成114+114块，每个块到最后只会对R1或者R2进行处理！
而且影响R1块的只有初始R2, R3, R8的结果，影响R2块的只有初始R1, R3, R8的结果。这意味着每一对R1, R2经过一对R1/R2 block后，都会映射到新的R1, R2。继续看修改R3, R8的操作，发现其不会受R1, R2的值污染，因此每一轮中参数(R3, R8)的值固定，能不能反向推理出原始参数呢？

很遗憾，改变R1/R2的步骤中包含丢失信息的操作 (用到了|, &，没有移位操作)，因此反向推理会在局部产生多解，但是也可能发送剪枝，到最后形成唯一的解。

当时我沉迷于“分块”的发现，因为以前没有使用过z3，对其性能没有把握，想要使用z3求解每个块，逐步推理。但这样的算法比较棘手，我也到这里放弃了。

然而赛后大佬的wp是直接用z3求解整个块
> [TODO]
学习使用z3，尝试