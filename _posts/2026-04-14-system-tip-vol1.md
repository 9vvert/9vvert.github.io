---
title: System Tips - Vol1
categories: [tips, system]
tags: [trick, system]
---

### aur缓存
在下载一个包的时候，卡在了最后一步，我用Ctrl-C打断，但是接下来重新下载的时候一直报错.
```
：error: failed to commit transaction (could not find or read package)
  [##############################-----------------------------]  52%
  Errors occurred, no packages were upgraded.
   -> error installing repo packages
  error installing repo packages
```
这大概率是某个依赖的包下载不完整的时候，强制将其停止，导致污染了缓存.

解决方法：
```
sudo pacman -Scc 	# 清理本地/var/cache/pacman/pkg/ 下的缓存包
sudo pacman -Syy	# 刷新缓存
```
注意：其中的`c`, `y`参数本身能够发挥功能，双写表示“强制”

### pacman/yay时的python环境.
在某一次安装包的时候，出现问题：
```
  ERROR Missing dependencies:
          wheel
  ==> ERROR: A failure occurred in build().
      Aborting...
   -> Failed to install layer, rolling up to next layer.error:error making: python-lzo - exit status 4
  warning: python-poetry-2.3.4-1 is up to date -- reinstalling
  resolving dependencies...
  looking for conflicting packages...
```
AI给的回答是：aur作为系统包，很多设置是围绕系统里的python设置的，因此安装的时候最好不要在虚拟环境中进行.
进行`uv deactivate`后，成功安装.

### 新terminal的“working-dir inherit”
目前使用的环境是niri + ghostty，绑定`super + u`来启动一个新的terminal
但是这种launch方法本身并不支持环境继承（因为其致力于在任意情况下启动新的terminal，有时候focus并不在某一个现有的terminal上面，所以只能用一些通用的方法）
后来发现ghostty本身默认的快捷键有`ctrl+shift+n`启动新window,并且会继承工作目录.

[TODO]能否用一个命令自动判断两种情况？虽然在niri中能够捕捉focus的窗口并判断，但是ghostty的行为似乎有些古怪，比如可能在一个`~/abc`的ghostty terminal中按下后，第一个instance还是在`~`；但是再切回`~/abc`启动第二个，就会开始继承了. 还有待探索