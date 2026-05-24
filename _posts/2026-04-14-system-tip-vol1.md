---
title: System Tips - Vol1
categories: [system, tips]
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

### WM环境下的polkit
在linux下执行vmware的时候，发现点击network config选项的时候，一直没有反映。猜测是权限问题，用命令行启动，遇到：
```
==== AUTHENTICATING FOR org.freedesktop.policykit.exec ====
Authentication is needed to run `/usr/bin/vmware-netcfg 5 15 2271362' as the super user
Authenticating as: xxx
Password:
==== AUTHENTICATION FAILED ====
Error executing command as another user: Not authorized

This incident has been reported.
```
查阅资料发现，当前用户没有通过polkit提权. 但是systemctl检查polkit，是正常的。问题出在WM环境下，需要额外安装polkit认证代理，比如：
```
sudo pacman -S polkit-gnome
```
然后临时启动，或者加入WM启动脚本中：
```
/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
```
然后再点击高权限按钮，成功弹出认证窗口.

### VMWare网络服务
VMWare添加了虚拟子网，但是ifconfig却找不到。怀疑VMWare network服务运行障碍，查看状态：
```
○ vmware-networks.service - VMware Networks
     Loaded: loaded (/usr/lib/systemd/system/vmware-networks.service; enabled; preset: disabled)
     Active: inactive (dead) since Sun 2026-05-24 05:40:44 EDT; 1min 39s ago
   Duration: 2d 22h 50min 42.488s
 Invocation: 9478bc637f7c4a388863d3be950312d8
    Process: 2286756 ExecStartPre=/sbin/modprobe vmnet (code=exited, status=1/FAILURE)
    Process: 2286761 ExecStart=/usr/bin/vmware-networks --start (code=exited, status=0/SUCCESS)
    Process: 2286778 ExecStop=/usr/bin/vmware-networks --stop (code=exited, status=0/SUCCESS)
   Mem peak: 4.7M
        CPU: 42ms

May 24 05:40:44 myarch vmware-networks[2286778]: Stopped NAT service on vmnet0
May 24 05:40:44 myarch vmware-networks[2286778]: Disabled hostonly virtual adapter on vmnet0
May 24 05:40:44 myarch vmware-networks[2286778]: Stopped DHCP service on vmnet1
May 24 05:40:44 myarch vmware-networks[2286778]: Disabled hostonly virtual adapter on vmnet1
May 24 05:40:44 myarch vmware-networks[2286778]: Stopped DHCP service on vmnet8
May 24 05:40:44 myarch vmware-networks[2286778]: Stopped NAT service on vmnet8
May 24 05:40:44 myarch vmware-networks[2286778]: Disabled hostonly virtual adapter on vmnet8
May 24 05:40:44 myarch vmware-networks[2286778]: Stopped all configured services on all networks
May 24 05:40:44 myarch systemd[1]: vmware-networks.service: Deactivated successfully.
May 24 05:40:44 myarch systemd[1]: Started VMware Networks.
```
手动执行启动流程，第一步就报错：
```
$ sudo modprobe vmnet
modprobe: FATAL: Module vmnet not found in directory /lib/modules/7.0.5-arch1-1
```
原来是没有和内核版本匹配的vmnet.ko.

```
sudo pacman -S linux-headers
```
然后重新编译VMWare模块：
```
sudo vmware-modconfig --console --install-all
```
但是这一步出错：
```
(venv14) woc@myarch:~ $ sudo vmware-modconfig --console --install-all
[AppLoader] GLib does not have GSettings support.

(process:2291083): GLib-CRITICAL **: 05:48:22.877: g_file_test: assertion 'filename != NULL' failed
Failed to setup build environment: Header path "(null)" is not a valid directory.
(venv14) woc@myarch:~ $ uname -r
7.0.5-arch1-1
(venv14) woc@myarch:~ $ pacman -Q linux linux-headers linux-lts linux-lts-headers linux-zen linux-zen-headers 2>/dev/null
linux 7.0.9.arch2-1
linux-headers 7.0.9.arch2-1
```
原来是当前运行内核版本和安装的linux-header不匹配. 需要重启才能使用新内核.
重启后重新编译VMWare模块.

最后加载：
```
sudo modprobe vmmon
sudo modprobe vmnet
```
无错误。
重启后VMWare网络正常工作