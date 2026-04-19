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