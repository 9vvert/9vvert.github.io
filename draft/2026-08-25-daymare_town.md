---
title: Flash小游戏《小镇的秘密》下载与反编译分析.
categories: [idea&try, GameReverse]
tags: [game, web]
---

### 0x01 swf文件下载 & 反编译工具
flash游戏是以`.swf`格式存在的. 猜测在点击一个游戏界面后会进行对应文件的请求，我们只需要在浏览器工具中把该文件找出来.

虽然4399页面有反调试（今天下午研究了下，破解后才发现根本不需要绕过反调试就能抓到目标文件），但还是可以查看源码。在`htm`文件中搜索`swf`, 可以找到疑似路径的部分：

```html
var _strGamePath = "/upload_swf/ftp/20100703wen/1.swf";
......

 <div id="swfdiv">
	<div id="pusher"></div>
	<center id="game">
		<SCRIPT LANGUAGE='javascript'>
			var str1 = '/upload_swf/ftp/20100703wen/1.swf';
			document.write("<OBJECT ID='flashgame' classid='clsid:D27CDB6E-AE6D-11cf-96B8-444553540000' codebase='' width='750' height='563'>");
			document.write("<PARAM NAME='allowScriptAccess' VALUE='never'>");
			document.write("<PARAM NAME='allowNetworking' VALUE='internal'>");
			document.write("<PARAM NAME='movie' VALUE='" + webServer + str1 + "'>");
			document.write("<embed id='flashgame1' name='flashgame' src='" + webServer + str1 + "' quality='high' pluginspage='//www.macromedia.com/go/getflashplayer' type='application/x-shockwave-flash' width='750' height='563' allowScriptAccess='nerver' allowNetworking='internal'></embed>");
			document.write("<PARAM NAME='quality' VALUE='high'>");
			document.write("</OBJECT>");
		</SCRIPT>
	</center>
</div>
```

调试获得webServer，完整路径为`https://s7.4399.com/4399swf/upload_swf/ftp/20100703wen/1.swf`, 可以直接下载（需要暂时关闭ruffle插件，否则面对swf文件时会调用ruffle运行，而不是下载到本地）；也可以在抓包界面找到.

而反编译swf文件使用`jpexs-decompiler` (`FFDec`)这个工具：
> https://github.com/jindrapetrik/jpexs-decompiler

### 0x02 初步探索

![](/assets/img/2026/daymare_town_sidebar.png)

shapes存储一些静态的形状；morphshapes是动态特效，对分析没什么用.

到了sprite就有点意思了，我们可以找到大量的"DefineSprite"，左下角的Needed Characters和Dependent Characters在展开后是别的Sprite, 也就是说，一些零碎的小Sprite组合成大Sprite, 一层层组织起来，都放在这里.

![](/assets/img/2026/daymare_town_sprite.png)

Frame部分存储了一些游戏“帧”

![](/assets/img/2026/daymare_town_frame.png)

script部分包含了和一些Button/Sprite/Frame等绑定的脚本. 

![](/assets/img/2026/daymare_town_script.png)

先从script开始探索，审查下面几个frame相关脚本：

```
// frame27, name: end
removeMovieClip("lighter");
removeMovieClip("hook_on_string");
removeMovieClip("yardstone_key");
removeMovieClip("golden_egg");
removeMovieClip("lighter_shadow");
removeMovieClip("hook_on_string_shadow");
removeMovieClip("yardstone_key_shadow");
removeMovieClip("golden_egg_shadow");
if(secret != false)
{
   oops._visible = false;
}
else
{
   oops._visible = true;
}
onEnterFrame = function()
{
   if(walker._x < 0)
   {
      walker.stop();
      walker._visible = false;
   }
   else
   {
      walker._x -= 0.5;
   }
};
```

这里似乎出现了一个"secret"变量，全局搜索它，找到使它为True的代码, 发现在 `DefineSprite 748`的DoAction中：
```
root.playSound("solved");
root.secret = true;
```

这个sprite似乎是一个囚犯，我们应该需要找到它（在前面的Sprite部分就是748，这里为了节省空间不重复插入了~）.

### 0x03 道具交互分析

重点是frame20的脚本，显然是道具交互逻辑.

```
function checkBird(num)
{
   if(eval("rooms.r" + num).bird._visible == false)
   {
      playSound("bird");
      rooms.r67.statue.nextFrame();
      eval("rooms.r" + num); //unpopped
      bird.bird._visible = true;
   }
   warp(num);
}
function checkHitTest(ktoryPrzedmiot)
{
	// 如果当前道具是hook， 遇到piece_of_string, 消耗这两个物品，得到hook_on_string
   if(ktoryPrzedmiot == "hook")
   {
      if(hook.hitTest(piece_of_string))
      {
         used(piece_of_string);
         used(hook);
         collectInit("hook_on_string");
      }
   }
   if(ktoryPrzedmiot == "piece_of_string")
   {
      if(piece_of_string.hitTest(hook))
      {
         used(piece_of_string);
         used(hook);
         collectInit("hook_on_string");
      }
   }
   if(ktoryPrzedmiot == "hook_on_string")
   {
      if(!hook_on_string.hitTest(rooms.r21.chinese_puzzle_block_1.tester))
      {
         if(hook_on_string.hitTest(rooms.r17.sinkmouth_key.tester))
         {
            rooms.r17.sinkmouth_key.play();
            hook_on_string._visible = false;
         }
      }
      else
      {
         rooms.r21.chinese_puzzle_block_1.play();
         hook_on_string._visible = false;
      }
   }
   if(ktoryPrzedmiot == "cloth")
   {
      if(cloth.tester.hitTest(screwdriver.tester))
      {
         used(cloth);
         used(screwdriver);
         collectInit("small_torch");
      }
   }
   if(ktoryPrzedmiot == "screwdriver")
   {
      if(screwdriver.tester.hitTest(cloth.tester))
      {
         used(cloth);
         used(screwdriver);
         collectInit("small_torch");
      }
   }
   if(ktoryPrzedmiot == "small_torch")
   {
      if(small_torch.hitTest(rooms.r23.torch.tester))
      {
         rooms.r23.torch.play();
         used(small_torch);
      }
   }
   if(ktoryPrzedmiot == "lighter")
   {
      if(lighter.hitTest(rooms.r23.torch.tester2))
      {
         rooms.r23.torch.nextFrame();
         playSound("matches");
      }
   }
   if(ktoryPrzedmiot == "small_coin")
   {
      if(small_coin.hitTest(rooms.r23.dzieciak.tester))
      {
         rooms.r23.dzieciak.play();
         used(small_coin);
      }
   }
   if(ktoryPrzedmiot == "plate")
   {
      if(plate.hitTest(rooms.r6.czek.tester))
      {
         rooms.r6.czek.play();
         used(plate);
      }
   }
   if(ktoryPrzedmiot == "book")
   {
      if(book.hitTest(rooms.r16.stwor.tester))
      {
         rooms.r16.stwor.gotoAndStop(3);
         used(book);
      }
   }
   if(ktoryPrzedmiot == "piece_of_paper")
   {
      if(piece_of_paper.hitTest(rooms.r37.stone.tester))
      {
         rooms.r37.stone.papier._visible = true;
         used(piece_of_paper);
      }
   }
   if(ktoryPrzedmiot == "sinkmouth_key")
   {
      if(sinkmouth_key.hitTest(rooms.r50.sejf.tester))
      {
         rooms.r50.sejf.play();
         used(sinkmouth_key);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_6")
   {
      if(chinese_puzzle_block_6.hitTest(rooms.r55.z1.tester))
      {
         rooms.r55.z1.gotoAndStop(2);
         used(chinese_puzzle_block_6);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_1")
   {
      if(chinese_puzzle_block_1.hitTest(rooms.r55.z2.tester))
      {
         rooms.r55.z2.gotoAndStop(2);
         used(chinese_puzzle_block_1);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_3")
   {
      if(chinese_puzzle_block_3.hitTest(rooms.r55.z3.tester))
      {
         rooms.r55.z3.gotoAndStop(2);
         used(chinese_puzzle_block_3);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_7")
   {
      if(chinese_puzzle_block_7.hitTest(rooms.r55.z4.tester))
      {
         rooms.r55.z4.gotoAndStop(2);
         used(chinese_puzzle_block_7);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_4")
   {
      if(chinese_puzzle_block_4.hitTest(rooms.r56.z5.tester))
      {
         rooms.r56.z5.gotoAndStop(2);
         used(chinese_puzzle_block_4);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_2")
   {
      if(chinese_puzzle_block_2.hitTest(rooms.r56.z6.tester))
      {
         rooms.r56.z6.gotoAndStop(2);
         used(chinese_puzzle_block_2);
      }
   }
   if(ktoryPrzedmiot == "chinese_puzzle_block_5")
   {
      if(chinese_puzzle_block_5.hitTest(rooms.r56.z7.tester))
      {
         rooms.r56.z7.gotoAndStop(2);
         used(chinese_puzzle_block_5);
      }
   }
   if(ktoryPrzedmiot == "yardstone_key")
   {
      if(yardstone_key.hitTest(rooms.r61.tester))
      {
         rooms.r61.tester._visible = false;
         used(yardstone_key);
      }
   }
   if(ktoryPrzedmiot == "golden_egg")
   {
      if(golden_egg.hitTest(rooms.r62.prisoner.tester))
      {
         rooms.r62.prisoner.play();
         used(golden_egg);
      }
   }
}
......
collectInit = function(co) {
	......
}

collect = function(co)
{
   zuzyty = eval("t" + numerek);
   zuzyty = true;
   attachMovie(co,[co + "_shadow"],numerek + 200);
   attachMovie(co,co,numerek + 300);
   eval(co + "_shadow")._alpha = 50;
   eval(co + "_shadow")._y = wysokoscMenu;
   eval(co + "_shadow")._x = numerek * rozstawMenu;
   eval(co)._x = eval(co + "_shadow")._x;
   eval(co)._y = eval(co + "_shadow")._y;
   eval(co).ktory = numerek;
   soundFX.gotoAndPlay("collect");
};
used = function(element)
{
   opisujemy = true;
   opis = "";
   playSound("used");
   Mouse.show();
   stopDrag();
   removeMovieClip(eval(element._name + "_shadow"));
   removeMovieClip(element);
};
```

这里的道具名都能在sprite中找到.

![](/assets/img/2026/daymare_town_items.png)

我们可以初步整理出下列内容：

```
hook + picec_of_string => 合成 hook_on_string
hook_on_string + room17的sinkmouse_key => 触发后者的play()，鱼钩变得invisible
hook_on_string + room21的chinese_puzzle_block1 => 触发后者的play(), 鱼钩变得invisible
//暂时不知道为什么这里有两个不同分支，而且鱼钩变成invisible后还能继续使用吗？

cloth + screwdriver => 合成small_torch
small_torch + room23的torch => 触发后者play()
lighter + room23的torch => 触发后者nextFrame()
small_coin + room23的dzieciak => 触发后者的play()
// 猜测这里是合成火把、插上去后，用打火机点燃, 然后才能看清楚，把硬币给小孩

book + room16的stwor => 触发后者gotoAndStop(3)

piece_of_paper + room37的stone => 设置后者的papier._visible = true

sinkmouth_key + room50的sejf => 设置后者的play()

chinese_puzzle_block 6 1 3 7 4 2 5 => 对应room56的z1-z7

yardstone_key + room61 => 解锁room61

golden_egg => prisoner => 触发后者的play(), 游戏通关
```
(后续发现`play()`应该只是播放动画)

但是，我们要怎么知道一个道具怎么在哪个房间拾取呢？

以golden_egg为例，搜索"golden_egg"并没有找到，那么试试搜索其道具编号31呢？

结果找到一个`DefineButton2 455`:
```
on(press){
   warp(31);
}
```

接着找455的depedent characters, 有Sprite 453, 可以看到它对应的frame1中关联了4个instance, 其中455对应地面，或许`warp(31)`代表传送到上一个房间，编号为31；

456对应黑色的区域，脚本为：
```
on(rollOver){
   root.opis = "吓了一跳";
}
```
作用是鼠标放上去的时候显示文字.
![](/assets/img/2026/daymare_town_button1.png)


道具编号也不行，还有什么方法是和拾取道具有关的呢？突然想到在道具合成的时候，有`collectInit("hook_on_string");`这种写法，尝试搜索`collectInit`，果然找到了大量结果.

![](/assets/img/2026/daymare_town_item_place.png)

在左侧搜索`100`，可以看到sprite 100只包含形状；而其parent, 也就是sprite 98, 才包含子instance的别名`small_coin`.

注意这里sprite 100是位于地图中的small_coin，我们之前看到有名字的sprite 6是道具栏中的small_coin.

用这个方法可以找到各个道具的位置：

```
100 -> small_coin, r2
102 -> hook, r2
109 -> piece_of_string, r4
114 -> yard_stone_key, r5
144 -> chinese_puzzle_block_4, r9
147 -> cloth, r9
160 -> screwdriver, r12
223 -> 222 -> 213 -> stwor, r16
241 -> sinkmouse_key, r17
267 -> chinese_puzzle_block_1, r21
297 -> 282 -> chinese_puzzle_block_3, r23
337 -> lighter, r25
411 -> piece_of_paper, r34
425 -> 421 -> 415 -> chinese_puzzle_block_2, r35
446 -> stone, r37，realated with chinese_puzzle_block_6
459 -> plate, r39
470 -> book, r41
520 -> chinese_puzzle_block_7, r51
799 -> golden_egg, r67
```
 
其中分析完所有单物品后，block5、6并未出现，继续追踪发现block6实际上和stone有关；而block5实在没有找到，后面发现是游戏bug(详见"bug修复"章节)

游玩过程中遇到一个按钮解密，找到其instance绑定的脚本:
```
czekButtonz = function()
{
   if(bu1._currentframe == 1 && bu2._currentframe == 20 && bu3._currentframe == 20 && bu4._currentframe == 40 && zak._currentframe == 1)
   {
      zak.play();
      root.playSound("stone1");
   }
};
``` 
需要判定四个按钮的方向；这里是使用frame来比较的，去找按钮的frame素材，可以知道1对应left， 20为up，40为right.


### 0x04 房间分析

房间在代码中以`rooms.rxx`形式引用，这无疑是至关重要的信息但。是搜索关键词`rooms`后，并没有找到房间编号和素材的对应。这意味着这类数据并不是以代码定义的，而是直接存储在某种数据文件中，比如某种instance. 询问ai得知swf中的instance应该是隶属于某些时间线，可以在先在frame中寻找。

果然很快在`frame20`下面发现一个PlaceObject2的名称为`rooms`, 对应的sprite编号为85

![](/assets/img/2026/daymare_town_rooms_instance.png)

可以找到各个编号对应的房间.

![](/assets/img/2026/daymare_town_room_sprite.png)

对应关系：
```
PlaceObject2 (chid: 86, dpt: 1, nm: "r1")
PlaceObject2 (chid: 98, dpt: 2, nm: "r2")
PlaceObject2 (chid: 105, dpt: 3, nm: "r4")
PlaceObject2 (chid: 111, dpt: 4, nm: "r5")
......
PlaceObject2 (chid: 857, dpt: 80, nm: "r80")
PlaceObject2 (chid: 862, dpt: 81, nm: "r81")
```


在前面我们初步探索了warp这个函数，猜测是房间传送，现在进行验证.

sprite 86是room1, 而井是room2. 现在找到触发条件转移的button, 编号为88.

![](/assets/img/2026/daymare_town_warp.png)

寻找`DefineButton2 88`的脚本，刚好是`warp(2)`，证明了这就是传送到特定房间的函数.

```
on(press){
   warp(2);
}
```

有时候知道了一个秘密房间的编号x, 但是搜索`warp(x)`并没有结果。那就反向思考，进入一个房间后是能够点击某处回到上一个房间的。那么寻找这个秘密房间对应的sprite, 查看其sub-instance，找其中的button, 看会传送到哪个房间，就说明可以从那里进入. 

### 0x05 secret获得
在游玩过程中发现主流程就是收集所有拼图。解包发现的golden_egg和prisoner的交互逻辑应该属于额外秘密彩蛋.

看来需要找10只鸟，才能收集金蛋.

找checkBird函数的引用.
```
\DefineButton2 (chid: 96)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 254)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 407)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 466)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 726)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 810)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 819)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 828)\BUTTONCONDACTION on(press)	
\DefineButton2 (chid: 837)\BUTTONCONDACTION on(press)
\DefineButton2 (chid: 846)\BUTTONCONDACTION on(press)	
```
发现触发条件是点击特定按钮，这些按钮都非常非常小，藏在特定场景中。不解包的话想集齐会相当折磨吧...

收集所有bird, 拿到金蛋：
![](/assets/img/2026/daymare_town_golden_egg.png)

释放prisoner, 这也就是游戏的secret:

![](/assets/img/2026/daymare_town_free_prisoner.png)

### 0x06 通关

收集所有拼图，

![](/assets/img/2026/daymare_town_puzzle_1.png)

![](/assets/img/2026/daymare_town_puzzle_2.png)

开启大桥，然后离开小镇.

![](/assets/img/2026/daymare_town_bridge.png)

![](/assets/img/2026/daymare_town_gameover.png)

此时已经凌晨4点了，我也要去睡觉了zzz

### 0x07 bug修复
游玩过程中发现点击打火机后会直接消失, 

![](/assets/img/2026/daymare_town_bug1.png)

原因是其脚本中增加物品使用的是`root.collectInit(_name);`函数，但是汉化组可能使用了机翻或者全局变量替换的方式，把这里的instance name也一同翻译了。拾取的时候`collectInit("打火机")`，但是没有对应的instance.

类似的还有拼图7、螺丝刀、石头等. 修改instance的属性，重新改成对应的英文即可解决.

但是有一个比较特殊的物品chinese_puzzle_block_5，捡起也会消失。发现其对应的instance直接没有"name"这个属性, 所以在`collectInit(_name)`的时候无法正确添加。而且因为原本就没有该属性，似乎无法在instance部分添加. 但是该物品绑定的AS脚本是可以修改的，将动态获得的`_name`修改成固定字符串即可.
```
onPress = function()
{
   root.opis = "";
   root.collectInit(_name);
   _visible = false;
   _visible = false;
};
onRollOver = function()
{
   root.opis = _name;
};
onRollOut = function()
{
   root.opis = "";
};
```

以及一个恶性bug: 道具栏最多15个槽位，但是用过的道具并不会释放槽位，导致很快达到上限，找到道具使用逻辑增加释放槽位的语句：`set("t" + element.ktory,false);`
```
used = function(element)
{
   opisujemy = true;
   opis = "";
   playSound("used");
   Mouse.show();
   stopDrag();
   set("t" + element.ktory,false);  // 新增
   removeMovieClip(eval(element._name + "_shadow"));
   removeMovieClip(element);
};
```

