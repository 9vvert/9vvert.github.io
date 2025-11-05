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


> test
{: .info }

> test
{: .tip }

> test
{: .warning }

> test
{: .danger }