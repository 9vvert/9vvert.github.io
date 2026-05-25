---
title: Crackme vol1 -- 01-acid-burn
categories: [reverse-chal, crackme]
tags: [reverse, crackme, windows]
---
逛吾爱破解论坛的时候，找到了crackme大礼包，决定练习一下。虽然现在ai时代，逆向基本不用交给人做了，但是我觉得还是有必要学习一些逆向思路，以及提高对工具的使用能力. 主要聚焦于代码定位，而解密部分现在已经几乎没有人工分析的必要了。

这一次的crackme编号为01, `Acid burn.exe`. 32bit程序, 语言Object Pascal(delphi)

### 校验1
#### 分析
![](/assets/rev-chall/crackme/01-check1.png)

先尝试静态分析, 第一个校验失败后显示'Sorry , The serial is incorect !', 在ida中搜索引用， 可以看到有两个校验条件.

![](/assets/rev-chall/crackme/01-check1-cfg.png)

所在函数为：0x42F998, 接着用x32dbg调试, 跳转到相应地址，但是发现其地址反汇编错误（这也体现了动态调试器对指令的分析准确度往往不如静态分析工具）:

![](/assets/rev-chall/crackme/01-check1-wrong-disasm.png)

需要手动纠正反汇编错误。在解析错误的指令0x42f996上，右键 -> analysis -> Treat from selection as -> byte, 我们需要把前2个字节强制当作数据，把长度设置成2，然后就能正确解析了.

动态调试的时候，随便输入一个测试name`abc !`, step over, 直到x32dbg中出现想要的数据（动态调试器很方便的一点就是能够实时显示使用到的各个寄存器/栈上的值）

![](/assets/rev-chall/crackme/01-check1-find-input.png)

接下来我用的测试对是`my_custom_name`, `a_random_passwd`. 在第一个校验条件下断点，检查要比较的寄存器，刚好是输入字符的长度，所以这里应该是长度判断，要求name长度不小于4.

![](/assets/rev-chall/crackme/01-check1-cmp-len.png)

继续往下走，发现直接出现了一个比较像序列号的字符串，看来是通过name派生的，后面的逻辑就是直接cmp了.

![](/assets/rev-chall/crackme/01-check1-cmp-serial.png)

#### 拓展：x32dbg全内存搜索
比较复杂的程序，可能需要我们在内存中搜索输入字符串来辅助定位。可以在dump窗口中，使用`ctrl-B`, 也就是搜索pattern的功能.
但是这样默认只会找当前dump窗口内的数据（范围有限），我找了很久也没有找到全内存搜索的按钮，但是发现了一个command:
`findallmem 0, "6D 79 5F 63 75 73 74 6F 6D"`
这个命令的第一个参数是起始内存地址，第三个参数是长度，默认是-1(也就是无限长往后搜索).

### 校验2
#### 窗口定位
用字符串定位法可以直接找到，如果以解题为目的就没有看的必要了。我想要尝试一下通过窗口控件来定位.
首先用spyxx来查找check按钮的句柄，然后在x32dbg的Handles窗口刷新：

![](/assets/rev-chall/crackme/01-check2-handles.png)

因为消息处理的回调函数逻辑一般都是在某个窗口中写的，所以我们要找button的父窗口(90704)对应的Proc地址0x4193bc.

![](/assets/rev-chall/crackme/01-check2-parent-proc.png)

但是这里看上去并没有经典的接受消息号，然后进行比较，选择执行哪个分支的逻辑。而是有一些SetWindow类的函数，看上去像一次性的初始化函数。通过调试也确实发现，这里只在初始化的时候能够断下来，后续点击按钮不再执行这里。AI告诉的结果是，这是delphi框架，和经典的windows GUI程序不太一样.

#### 方法1：正向出发，消息api定位
尝试找消息分发逻辑，比如找DispatchMessage, TranslateMessage等api.
静态分析工具中直接搜索DispatchMessageA函数的xref, 有唯一引用：
```c
int __fastcall sub_429DD4(int a1)
{
  int v2; // ebx
  _BYTE v4[4]; // [esp+0h] [ebp-28h] BYREF
  struct tagMSG Msg; // [esp+4h] [ebp-24h] BYREF

  v2 = 0;
  if ( PeekMessageA(&Msg, 0, 0, 0, 1u) )
  {
    LOBYTE(v2) = 1;
    if ( Msg.message == 18 )
    {
      *(_BYTE *)(a1 + 124) = 1;
    }
    else
    {
      v4[0] = 0;
      if ( *(_WORD *)(a1 + 158) )
        (*(void (__fastcall **)(_DWORD, struct tagMSG *, _BYTE *))(a1 + 156))(*(_DWORD *)(a1 + 160), &Msg, v4);
      if ( !(unsigned __int8)sub_429DA4(a1, &Msg)
        && !v4[0]
        && !(unsigned __int8)sub_429CF0(a1, &Msg)
        && !(unsigned __int8)sub_429D40(a1, &Msg)
        && !(unsigned __int8)sub_429CCC(a1, &Msg) )
      {
        TranslateMessage(&Msg);
        DispatchMessageA(&Msg);
      }
    }
  }
  return v2;
}
```
接着在x32dbg中找到对应位置，在DispatchMessage前下断点：

![](/assets/rev-chall/crackme/01-check2-before-dispatch.png)

注意DispatchMessageA的参数是Msg结构，其在32位下定义如下：
```
typedef struct tagMSG {
    HWND   hwnd;      // +0x00 接收消息的窗口句柄
    UINT   message;   // +0x04 消息编号
    WPARAM wParam;    // +0x08 参数1
    LPARAM lParam;    // +0x0C 参数2
    DWORD  time;      // +0x10 消息时间
    POINT  pt;        // +0x14 鼠标坐标
} MSG;
```
我们下断点的位置，`[esp+0xc]`对应message参数，通过下条件断点，我们可以过滤特定消息类型、特定组件（通过hwnd参数）的消息.
设置断点条件：`[esp+8] == 0x2407bc || [esp+8] == 0x270c60`，过滤接受消息的对象.

在调试观察的时候，发现点击按钮时，其不会收到0x111(WM_COMMAND), 但是会收到0x200(WM_MOUSEMOVE), 0x201(WM_LBUTTONDOWN), 0x202(WM_LBUTTONUP)等消息. 而且这3个消息的hwnd都是button, 而不是父窗口.
在0x202断下来，按下continue后，会弹出失败窗口.

在调用DispatchMessageA后，会进入比较复杂的system代码, 想要穿过这些system代码会费一番功夫。有没有能够直接执行完所有system代码，等回到用户态代码时停住的功能呢？x64dbg中，可以在身处system代码中，`Debug -> run to user code`, 或者`Alt+F9`， 可以看到，从DispatchMessageA开始，再次回到用户态时，执行的函数是button的点击处理函数，而且可以在这里找到serial比较逻辑.

![](/assets/rev-chall/crackme/01-check2-run-to-user.png)

#### 方法2：反向出发，MessageBox行为定位
能否根据调用栈功能来找到关键校验函数？x32dbg的调用栈会将函数在进入的时候入栈，退出的时候出栈，面对一个我们还不知道在哪里的目标函数，我们想要通过call stack来定位，就必须让函数停在更深的位置。很容易想到用MessageBoxA函数定位，有3处引用，可以全部打上断点观察。但是对于更加复杂的程序，这样会很麻烦。我们或许可以在比call更“集中”的地方下断点，比如双击call MessageBoxA, 进入IAT hook跳转代码。起初我以为这样下一个断点就万事大吉了，结果发现，这3处引用竟然产生了2个不同的IAT hook跳转口：

![](/assets/rev-chall/crackme/01-check2-iat-jmp1.png)
![](/assets/rev-chall/crackme/01-check2-iat-jmp2.png)

所以更好的方法是，再进入一层，直接在MessageBoxA的函数开头下断点：

![](/assets/rev-chall/crackme/01-check2-msgboxA.png)

这样之后观察call stack:

![](/assets/rev-chall/crackme/01-check2-callstack.png)

其中第二个就是调用MessageBoxA的函数，跟踪进去。同时在ida中可以看到这个函数叫做`int __usercall Tserial_button1Click@<eax>(int a1@<eax>, int a2@<ebx>)`, 其中的`sub_4039FC`进行了serial校验.

在callstack中也可以看到从DispatchMessage，是如何一步步执行到现在的，安装了x64dbg-MCP后，执行到这里后，让ai分析调用栈：
```
DispatchMessageA
 -> VCL/Delphi 窗口过程/消息分发
 -> 0x41B792 / 0x41CD40 / 0x41B43C 一层层做对象事件派发
 -> 0x42F470  按钮 OnClick 处理函数
 -> 0x42F4D0  比较 serial
 -> 0x42F4D5  根据比较结果跳成功或失败
 -> 0x42A170  MessageBoxA 包装
 -> MessageBoxA
```

### 总结
- 从资源定位：字符串、输入数据
- 从行为定位：根据弹窗等行为，进行api拦截.
- 窗口定位：熟悉消息处理过程，另外还有run to user code这个技巧