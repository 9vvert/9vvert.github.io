---
title: Nginx BROP 漏洞(CVE-2013-2028)复现 & Nginx反向代理搭建 & vagant使用
categories: [misc]
tags: [pwn, BROP]
---

这学期《网络空间安全导论》中，我选择了BROP实验，以前只在ctf wiki上见过它的名字，趁这个机会实践一下.

### 环境搭建step1: vagant部署带特定版本nginx的虚拟机
刚开始想用Docker搭，但是环境毕竟太老了，用源码编译会爆各种各样的问题。后来发现了 [kitctf/nginxpwn](https://github.com/kitctf/nginxpwn) 这个仓库，它提供了预编译好的nginx二进制文件（感觉这种上古漏洞的复现还是直接拿现成binary搭环境才行啊qwq）

我的电脑上已经有了virtualbox工具，接下来还需要安装`vagrant`:
```
yay -S vagrant
```
这是一个管理虚拟机环境的工具，接着进入nginxpwn目录下，可以看到有一个配置文件`Vagrantfile`：
```
# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # Configure the box
  config.vm.box = "ubuntu/trusty64"
  config.vm.hostname = "nginx"

  # Configure SSH access
  config.ssh.username = "vagrant"

  # Webserver
  config.vm.network "forwarded_port", guest: 80, host: 8080

  config.vm.provision "shell", inline: <<-SHELL
    apt-get -y install gdb
    cp -r /vagrant/usr_local_nginx /usr/local/nginx
    echo "FLAG{your_flag_here}" > /flag
    echo "All done, start nginx with 'sudo /vagrant/bin/nginx1'"
  SHELL

end
```
大致内容就是选择了一个ubuntu虚拟机作为base, 设置宿主机的8080端口->虚拟机的80端口转发.
检查一下当前目录：
```
$ ls
bin  nginx-src  poc.py  README.md  usr_local_nginx  Vagrantfile
```
可以推断，当前目录会被映射到虚拟机中的`/vagrant`，然后把预编译的nginx和一些配置文件放到对应的位置.

我们执行
```
vagrant up
```
命令就会根据上面的配置文件来构建一个虚拟机.

接着用
```
vagrant ssh
```
来登录，进入到虚拟机中。（关系类似`docker build`和`docker run`）

服务器中运行`nginx2`（带canary的版本）：
```
sudo /vagrant/bin/nginx2
```
然后在宿主机上进行测试：
```
$ curl 127.0.0.1:8080
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

### 环境搭建step2: 部署