---
title: cow clicker
categories: [ctf2025, v1tCTF]
tags: [reverse, web, misc, new-format]
toc: false
---

### 0x01
页面要求点击1000000000次, 通过控制台查看，使用了flutter。 搜索核心字符串，发现在main.dart.wasm里
![](/assets/ctf/2025/cow_clicker_search_first.png)

尝试使用wasm cheat engine， 但是没有找到能用的（

下载main.dart.wasm，然后用ghidra wasm plugin或者wasm2wat，但都无法打开。

赛后有大佬解释了原因：
> Yeah https://github.com/WebAssembly/wabt/issues/2348, basically use https://github.com/bytecodealliance/wasm-tools instead

接下来需要进一步分析wasm文件。

>能否直接找flag相关逻辑？
如果最后的flag是向外部请求，能否直接搜索http关键字？（失败，而且最后可能是本地解密）

但是顺着这个思路，搜索关键词1000000000，大约有20个匹配的结果，但是大部分都是f64类型。重点关注其中的i64类型，找到了比较跳转逻辑：
![](/assets/ctf/2025/cow_clicker_search_const.png)

```wasm
   local.get $var2
    struct.get $type281 $field7
    i64.const 1000000000
    i64.lt_s
    if
      local.get $var3
      global.get $global13338
      i32.const 333
      i64.const 1000000000
      local.get $var2
      struct.get $type281 $field7
      i64.sub
      struct.new $type7
      global.get $global13339
      call $func727
      ref.null none
      global.get $global13340
      ref.null none
      call $func7022
      call $func963
      drop
    end
    local.get $var2
    struct.get $type281 $field7
    i64.const 1000000000
    i64.ge_s
    if
      ......
    end
```
可以猜到click counter存在于 `local $var2.$field7`
其中`struct.get $type281 $field7`表示 将栈上的类型强转为`$type281`，然后取出某个值

可以猜测第一个 `counter < x`的逻辑用来显示下面“还剩几次”，而第二个`couter >= x`用来进一步的逻辑

尝试直接用chrome dev tools来修改值，但是似乎不会影响wasm运行时栈上的内容（可能是安全措施，禁止修改？但理论上应该能绕过）


>既然无法直接用控制台改变已经固定的wasm相关逻辑，那就直接从源头修改wasm


### 0x02 使用Burpsuite拦截替换wasm response
最容易想到的是直接把第二个判断`i64.ge_s`改成`i64.lt_s`，

> 在Burpsuite尝试抓包的时候，需要清除前面的缓存，否则某些资源可能会从本地拿取。但是浏览器缓存也有好处，当自己完成一次缓存投毒后，接下来的访问就不用每次都进行修改，即可自动使用修改后的wasm

然而只是出现了一个flag checker:

![](/assets/ctf/2025/cow_clicker_checker.png)

输入失败会显示“doesn't seem correct”
直接复制dev tool解析的wasm代码，然后全文搜索关键词：
```
......
 (global $S.Good_job!_You_got_the_flag!_Mo0o0oo0oo! (;4082;) (import "S" "Good job! You got the flag! Mo0o0oo0oo!") externref)
(global $S.Nah__doesn't_seem_correct. (;4083;) (import "S" "Nah, doesn't seem correct.") externref)
......
(global $global13580 (ref $type560) (i32.const 1536) (i32.const 0) (ref.null none) (i32.const 1509) (i32.const 0) (ref.null none) (i32.const 4) (i32.const 0) (global.get $S.Good_job!_You_got_the_flag!_Mo0o0oo0oo!) (struct.new $type2) (ref.null none) (ref.null none) (ref.null none) (ref.null none) (struct.new $type559) (ref.null none) (struct.new $type560))
(global $global13581 (ref $type560) (i32.const 1536) (i32.const 0) (ref.null none) (i32.const 1509) (i32.const 0) (ref.null none) (i32.const 4) (i32.const 0) (global.get $S.Nah__doesn't_seem_correct.) (struct.new $type2) (ref.null none) (ref.null none) (ref.null none) (ref.null none) (struct.new $type559) (ref.null none) (struct.new $type560))
```
上面的代码应该是定义了一些常量，下面用常量来初始化一些object （可能是窗口函数的资源加载）

接着搜索 `$global13580`和`$global13581`:
```
  (func $func8329 (param $var0 (ref struct)) (result (ref null $type0))
    (local $var1 (ref $type281))
    (local $var2 (ref $type1595))
    (local $var3 (ref $type2))
    (local $var4 (ref $type2))
    local.get $var0
    ref.cast $type1595
    local.tee $var2
    struct.get $type1595 $field0
    local.tee $var1
    struct.get $type281 $field14
    local.get $var2
    struct.get $type1595 $field1
    ref.as_non_null
    call $func1520
    call $strcat_func743
    local.get $var1
    struct.get $type281 $field15
    call $strcat_func743
    local.set $var3
    block $label1 (result i32)
      block $label0
        local.get $var1
        struct.get $type281 $field13
        call $func4803
        local.tee $var4
        struct.get $type2 $field0
        i32.const 4
        i32.ne
        br_if $label0
        local.get $var3
        struct.get $type2 $field2
        local.get $var4
        struct.get $type2 $field2
        call $wasm:js-string.equals
        i32.eqz
        br_if $label0
        i32.const 1
        br $label1
      end $label0
      i32.const 0
    end $label1
    if (result (ref $type561))
      local.get $var1
      call $func4099
      call $func8330
      global.get $global13580           // object initialized with "good job"
      call $func8332
    else
      local.get $var1
      call $func4099
      call $func8330
      global.get $global13581           // object initialized with "doesn't correct"
      call $func8332
    end
```
wasm中的if会根据栈上的值来判断，通常由上一步来设置。这里显然有`call $wasm:js-string.equals`
调试后发现这里的数据`v1t{xxxx}`，中间是乱码，猜测可能是数据解密和counter有关，验证发现确实如此.

> TODO 

### 0x03 二次patch
接下来尝试修改数据。
尝试寻找`local $var2`的源头，但是一层层向上追踪，实在不容易找到。
能不能直接修改`var2`来实现对counter的修改呢？毕竟为了效率，对于object的参数传递一般都是引用，可以一试。

最适合的地方就是`i64.ge_s`前面的一段代码，是`struct.get`，可以尝试置换成`struct.set`

把
```
local.get $var2
struct.get $type281 $field7   
i64.const64 1000000000
i64.ge_s
if
    ...
end
```
修改成
```
local.get $var2
i64.const64 1000000000
struct.set $type281 $field7   
nop
nop
nop(忘了几个nop了，反正就就是把if给覆盖掉)
    ...
nop
```
以前没怎么接触过wasm字节码，但是可以模仿其它的指令字节码，比如把 `struct.get`变成`struct.set`只需要修改指令的第二个字节。

另外发现wasm中的if指令没有指定跳转的目标地址，原来是使用`if - end`配对机制，所以需要把后面的`end`对应`0x0B`字节也给patch掉

接着再次替换，调试即可获得flag
![](/assets/ctf/2025/cow_clicker_success.png)