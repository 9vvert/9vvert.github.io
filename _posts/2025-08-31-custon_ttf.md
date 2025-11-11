---
title: tfcCTF - custom.ttf
categories: [ctf2025, TFCCTF]
tags: [reverse, misc, new-format]
toc: false
---

### 0x1 打开.ttf文件
题目附件给了一个`custom.ttf`,外加一个html文件。打开后提示：输入正确的flag会显示`O`。
然而经过尝试，发现一些数字组合会显示`X`，比如连续输入`ab`，显示的是字母`X`。而且进一步测试可以发现只有`[0-9a-f]`之间的组合才有这样的反应。
看来问题出在这个自定义的字体文件，下一步我们要尝试打开它。

然而直接搜索 "how to open .ttf file" 出现的网站大多是让你预览字体的，并不是真正解析其内容。更深层地搜索发现了 fontTool这个工具，其中带有的 ttx命令能够将`.ttf`文件解析成`xml`的格式。

但是直接输入命令会报错：
```shell
(venv13) woc@myarch:/ctf/TPC $ ttx Arial-custom.ttf
Dumping "Arial-custom.ttf" to "Arial-custom#3.ttx"...
Dumping 'GlyphOrder' table...
Dumping 'head' table...
Dumping 'hhea' table...
Dumping 'maxp' table...
Dumping 'OS/2' table...
Dumping 'hmtx' table...
Dumping 'LTSH' table...
Dumping 'VDMX' table...
Dumping 'hdmx' table...
ERROR: Unhandled exception has occurred
Traceback (most recent call last):
  File "/usr/lib/python3.13/site-packages/fontTools/ttx.py", line 464, in main
    process(jobs, options)
    ~~~~~~~^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/site-packages/fontTools/ttx.py", line 446, in process
    action(input, output, options)
    ~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/site-packages/fontTools/misc/loggingTools.py", line 375, in wrapper
    return func(*args, **kwds)
  File "/usr/lib/python3.13/site-packages/fontTools/ttx.py", line 304, in ttDump
    ttf.saveXML(
    ~~~~~~~~~~~^
        output,
        ^^^^^^^
    ...<6 lines>...
        newlinestr=options.newlinestr,
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/usr/lib/python3.13/site-packages/fontTools/ttLib/ttFont.py", line 288, in saveXML
    self._saveXML(writer, **kwargs)
    ~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/site-packages/fontTools/ttLib/ttFont.py", line 347, in _saveXML
    self._tableToXML(tableWriter, tag, splitGlyphs=splitGlyphs)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/site-packages/fontTools/ttLib/ttFont.py", line 379, in _tableToXML
    table.toXML(writer, self)
    ~~~~~~~~~~~^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/site-packages/fontTools/ttLib/tables/_h_d_m_x.py", line 95, in toXML
    row.append(widths[glyphName])
               ~~~~~~^^^^^^^^^^^
  File "/usr/lib/python3.13/site-packages/fontTools/ttLib/tables/_h_d_m_x.py", line 21, in __getitem__
    return self._array[self._map[k]]
           ~~~~~~~~~~~^^^^^^^^^^^^^^
IndexError: array index out of range
```

似乎是某个结构的问题，尝试跳过这个结构。搜索错误信息，最后得知`-x`可以跳过某个table,
```shell
ttx -x hdmx Arial-custom.ttf
```
即可成功提取文件。

### 0x2 定位核心结构
打开xml文件，非常巨大。大致浏览一下，发现了疑似字符定义的结构：
```xml
    ......
    <GlyphID id="19" name="zero"/>
    <GlyphID id="20" name="one"/>
    <GlyphID id="21" name="two"/>
    ......
    <GlyphID id="36" name="A"/>
    <GlyphID id="37" name="B"/>
    <GlyphID id="38" name="C"/>
    ......
    <GlyphID id="1320" name="O33a5128615982df4ef4afa3660216dcd"/>
    <GlyphID id="1321" name="O8dff2056a9fe8fe35cc04ed3a2d7fb2e"/>
    <GlyphID id="1322" name="O0f3e3d31bfe3af0330252b97337e67f9"/>
    <GlyphID id="1323" name="Ocb387301f3e9f21415e7bdb3c48dce60"/>
    <GlyphID id="1324" name="Oaa18d67eab8601f3df4bbb2a0e57f197"/>
    <GlyphID id="1325" name="O836c6d1fbe3c372e3770e7f7928f2470"/>
    ......
```
其中后面出现了很多以 `O` 开头的 name, 非常可疑

然而再往后，就暂时没发现什么了。文件太大，不能再这样慢慢看了，必须寻找突破口才行。

既然我们发现了一些字符会合并成`X`，不妨了解一下`.ttf`文件中字符合并的机制。询问了AI后给的提示是`gsub`和`liga`.
搜搜关键词，发现下列结构：
```xml
    ......
      </Lookup>
      <Lookup index="425">
        <LookupType value="4"/>
        <LookupFlag value="0"/>
        <!-- SubTableCount=1 -->
        <LigatureSubst index="0">
          <LigatureSet glyph="Oce28f52443b0b7d46641104a530cff76">
            <Ligature components="O4f89a36f34d49e17cf0466a08320f0a4" glyph="Oe120e61de984b0d0f55668c683df60b1"/>
          </LigatureSet>
        </LigatureSubst>
      </Lookup>
      <Lookup index="426">
        <LookupType value="4"/>
        <LookupFlag value="0"/>
        <!-- SubTableCount=1 -->
        <LigatureSubst index="0">
          <LigatureSet glyph="Of4a266d1f1053e57123aa2671524f943">
            <Ligature components="O6013f29b1db6e7f486afc564156027d9" glyph="O767147a15432e159f426931eecfd8464"/>
          </LigatureSet>
        </LigatureSubst>
      </Lookup>
      ......
```
而且如果继续寻找，可以发现：
```xml
      <Lookup index="488">
        <LookupType value="4"/>
        <LookupFlag value="0"/>
        <!-- SubTableCount=1 -->
        <LigatureSubst index="0">
          <LigatureSet glyph="a">
            <Ligature components="b" glyph="O3599087384ddd4e661af345dd7204791"/>
          </LigatureSet>
        </LigatureSubst>
      </Lookup>
```
猜测可能是把a和b合并成下面的 `Oxxx`字符，查阅资料后验证了这一猜想。

### 0x3 解析合成路径
这个查找表大约有2000多项，想要人工分析是不可能的。但其合并原理非常简单，只需要写一个解析器即可。在此之前，为了避免上层复杂的结构影响，只把这些Lookup结构提取出来新建一个文件，然后编写递归解析器：
```python
import xmltodict
import copy
class rule:
    src = ''
    dst = ''
    lhs = ''
    rhs = ''
    def __init__(self, lookup = None):
        if lookup != None:
            self.lhs = lookup['LigatureSubst']['LigatureSet']['@glyph']
            self.rhs = lookup['LigatureSubst']['LigatureSet']['Ligature']['@components']
            self.dst = lookup['LigatureSubst']['LigatureSet']['Ligature']['@glyph']
    def setval(self, dst, src):
        self.dst = dst
        self.src = src

with open('./Arial-custom#2.ttx','r') as f:
    data = xmltodict.parse(f.read())

rule_set = []
basic_table = [ 'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'a', 'b', 'c', 'd', 'e', 'f' ]
    

# 建立查找表
lookup = {}
index = 0
for i in range(16):
    basic_rule = rule()
    basic_rule.src = hex(i)[-1]
    basic_rule.dst = basic_table[i]
    rule_set.append(basic_rule)
    lookup[basic_rule.dst] = index
    index += 1
for item in data['LookupList']['Lookup']:
    new_rule = rule(item)
    rule_set.append(new_rule)
    lookup[new_rule.dst] = index
    index += 1

count = index

finish_flag = False
while not finish_flag:
    for i in range(count):
        rule = rule_set[i]
        if rule.src == '':
            l_index = lookup[rule.lhs]
            r_index = lookup[rule.rhs]
            l_src = rule_set[l_index].src
            r_src = rule_set[r_index].src
            if l_src != '' and r_src != '':
                rule.src = l_src + r_src
    
    finish_flag = True
    for i in range(count):
        rule = rule_set[i]
        if rule.src == '':
            finish_flag = False
    

for rule in rule_set:
    print(rule.dst, rule.src)
```
设立的终止条件是所有字符都解析完毕，其实刚开始不知道会不会存在不完全定义的字符，但是运行后发现并没有这种情况。 nice !

输出的结果：
```
......
O057d584568bdb375a6d2878ed5828e71 1b3102f1f72ffa176fa84955171d2d3528d1f84c1d7201fa76549a935249d455
Oef4698d565109903dad04e822b83054c aee72fa2
O8ca7e916a288f9ab6144086974798f59 1d6347e4556e7654f72f5867a5f8bd7aef4864bd8a6d68a20d728cf478cb4aab
O6c7dc4e1bc61eef8c425cb9492781003 40cf
O00677681b5d807ae8a23f821b5835888 84
Od37ba43eb880c76fd73cf4d8044d97ad 181fb2c0e0c9e9442a2c783b01c083d2
O2127b6ff4b4f1474defe864e1f7e129b c18b43be49558a69b90f64bd5249716fb41240cf05a3fa46bc0016e6086a2e2d
O537153cb2b2adbc547f58079fdebc3fa c66b
O032533cae9a2652fb9058539bd0866e7 ac76634902811e1eefd86f4668a294ad
Oec7204547efc1bcdffa99596e77dd0a7 b4128571480a8f3f24a3dd39358d8f3f
Oaeac87d0251e9b079380a5087b5aaac7 a6179d44
O19362495f4d4fd99e3c0253966db5746 14
Od2c3c49a6f15de1cdcb57b9fb8aaf786 e52ead0fc4d1aee7
O2c952af35ff66515283cbd46dea87ef9 28d1f84c1d7201fa76549a935249d4555ca39f5ee38b8e0d0044324eb9d940cf
O1589dc161adb6e82f096a2e5abfc1d19 169349a0e2820a8711cdacf6d6bb8a69
O289da697b2f65598b448e2807657eb5e 9f6375601d79904c
cd9c9dec155c128f96334a8231592e2d1b9d053747e474efbb6f1d72
......
```

### 0x4 寻找目标字符
结果非常多，但是哪一个是我们想要的呢？

这些自定义的字符中，应该有很多是`X`的形状，我们的目标是合成出具有`O`形状的字符。字体文件中一定有某个结构定义了字符怎么渲染，随便找一个`name`进行关键词搜索，能够发现下列结构：
```xml
<TTGlyph name="O3599087384ddd4e661af345dd7204791" xMin="9" yMin="0" xMax="1353" yMax="1466">
      <contour>
        <pt x="9" y="0" on="1"/>
        <pt x="576" y="764" on="1"/>
        <pt x="76" y="1466" on="1"/>
        <pt x="307" y="1466" on="1"/>
        <pt x="573" y="1090" on="1"/>
        <pt x="656" y="973" on="0"/>
        <pt x="691" y="910" on="1"/>
        <pt x="740" y="990" on="0"/>
        <pt x="807" y="1077" on="1"/>
        <pt x="1102" y="1466" on="1"/>
        <pt x="1313" y="1466" on="1"/>
        <pt x="798" y="775" on="1"/>
        <pt x="1353" y="0" on="1"/>
        <pt x="1113" y="0" on="1"/>
        <pt x="744" y="523" on="1"/>
        <pt x="713" y="568" on="0"/>
        <pt x="680" y="621" on="1"/>
        <pt x="631" y="541" on="0"/>
        <pt x="610" y="511" on="1"/>
        <pt x="242" y="0" on="1"/>
      </contour>
      <instructions>
        <assembly>
          NPUSHB[ ]	/* 41 values pushed */
          38 18 1 25 1 22 11 2 41 18 41 19 56 1 55 3 56 8 56 9 56 13 58 14 53
          18 55 19 10 18 19 32 18 33 52 18 32 18 33 52 14
          PUSHW[ ]	/* 1 value pushed */
          -32
          PUSHB[ ]	/* 4 values pushed */
          18 33 52 13
          ......
        </assembly>
      </instructions>
    </TTGlyph>
```
看上去很像某种坐标，资料显示这些结构定义了字体的轮廓。因此我们只需要找出那个形状像`O`的字符即可！
刚开始我还假设了一种情况，就是最终字符只是形状比较像字符`O`，但是点阵数据不同。但是自定义的2000多个字符大概率是用的同一个模板，只需要解析xml中点阵数据，找出“小众”的一些点，然后去实验即可。

然而这一题比较仁慈，直接用字母`O`的数据第一行去搜索即可定位到唯一的自定义字符：
```xml
 <TTGlyph name="O" xMin="99" yMin="-25" xMax="1501" yMax="1492">
      <contour>
        <pt x="99" y="714" on="1"/>
        <pt x="99" y="1079" on="0"/>
        <pt x="491" y="1492" on="0"/>
        <pt x="801" y="1492" on="1"/>
        <pt x="1004" y="1492" on="0"/>
        <pt x="1330" y="1298" on="0"/>
        <pt x="1501" y="951" on="0"/>
        <pt x="1501" y="731" on="1"/>
        <pt x="1501" y="508" on="0"/>
        <pt x="1321" y="156" on="0"/>
        <pt x="991" y="-25" on="0"/>
        <pt x="800" y="-25" on="1"/>
        <pt x="593" y="-25" on="0"/>
        <pt x="267" y="175" on="0"/>
        <pt x="99" y="521" on="0"/>
      </contour>
      <contour>
        <pt x="299" y="711" on="1"/>
        <pt x="299" y="446" on="0"/>
        <pt x="584" y="141" on="0"/>
        <pt x="799" y="141" on="1"/>
        <pt x="1018" y="141" on="0"/>
        <pt x="1301" y="449" on="0"/>
        <pt x="1301" y="732" on="1"/>
        <pt x="1301" y="911" on="0"/>
        <pt x="1180" y="1178" on="0"/>
        <pt x="947" y="1325" on="0"/>
        <pt x="802" y="1325" on="1"/>
        <pt x="596" y="1325" on="0"/>
        <pt x="299" y="1042" on="0"/>
      </contour>
      ......
</TTGlyph>    
```

```xml
 <TTGlyph name="O162e219bca79a462f9cf5701124cf74c" xMin="99" yMin="-25" xMax="1501" yMax="1492">
      <contour>
        <pt x="99" y="714" on="1"/>
        <pt x="99" y="1079" on="0"/>
        <pt x="491" y="1492" on="0"/>
        <pt x="801" y="1492" on="1"/>
        <pt x="1004" y="1492" on="0"/>
        <pt x="1330" y="1298" on="0"/>
        <pt x="1501" y="951" on="0"/>
        <pt x="1501" y="731" on="1"/>
        <pt x="1501" y="508" on="0"/>
        <pt x="1321" y="156" on="0"/>
        <pt x="991" y="-25" on="0"/>
        <pt x="800" y="-25" on="1"/>
        <pt x="593" y="-25" on="0"/>
        <pt x="267" y="175" on="0"/>
        <pt x="99" y="521" on="0"/>
      </contour>
      <contour>
        <pt x="299" y="711" on="1"/>
        <pt x="299" y="446" on="0"/>
        <pt x="584" y="141" on="0"/>
        <pt x="799" y="141" on="1"/>
        <pt x="1018" y="141" on="0"/>
        <pt x="1301" y="449" on="0"/>
        <pt x="1301" y="732" on="1"/>
        <pt x="1301" y="911" on="0"/>
        <pt x="1180" y="1178" on="0"/>
        <pt x="947" y="1325" on="0"/>
        <pt x="802" y="1325" on="1"/>
        <pt x="596" y="1325" on="0"/>
        <pt x="299" y="1042" on="0"/>
      </contour>
      ......
 <TTGlyph>
```

然后在我们已经得到的结果中搜索即可得到：
```
O162e219bca79a462f9cf5701124cf74c 1f89a957a0816e3bea3fa026cd9a47cf181fb2c0e0c9e9442a2c783b01c083d2
```

将后面的长串输入到网页中，确实显示了一个`O`， 成功！
