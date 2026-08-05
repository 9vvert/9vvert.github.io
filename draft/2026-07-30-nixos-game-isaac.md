---
title: NixOS Game Exploration
categories: [note, system]
tags: [note, system, game]
---

### 0x01 Install Steam in NixOS
I am more than excited to find that there have already been `steam` in nixpkgs.

Just follow the instructions in 

> https://wiki.nixos.org/wiki/Steam

Our games are installed in `~/.local/share/Steam/steamapps/common/`.

### 0x02 Solve the Luanching Failure: The Binding of Isaac
There is a crash log:

```
    PID: 6772 (isaac.x64)
           UID: 1000 (woc)
           GID: 100 (users)
        Signal: 11 (SEGV)
     Timestamp: Thu 2026-07-30 10:35:32 CST (7s ago)
  Command Line: ./isaac.x64
    Executable: /home/woc/.local/share/Steam/steamapps/common/The Binding of Isaac Rebirth/isaac.x64
    ......
```

Then let's try to launch it manually to get more debug info.

```
steamapps/common/The Binding of Isaac Rebirth (nu)                     [.venv14]
[woc@nixos]> ll
.rwxr-xr-x 8.5M woc 27 Jul 14:31 isaac.i386
.rwxr-xr-x  11M woc 27 Jul 14:31 isaac.x64
drwxr-xr-x    - woc 27 Jul 14:31 lib32
drwxr-xr-x    - woc 27 Jul 14:31 lib64
drwxr-xr-x    - woc 27 Jul 14:31 resources
.rwxr-xr-x   83 woc 27 Jul 14:30 run-i386.sh
.rwxr-xr-x   82 woc 27 Jul 14:31 run-x64.sh
.rw-r--r--  243 woc 30 Jul 10:35 savedatapath.txt
drwxr-xr-x    - woc 27 Jul 14:31 tools

steamapps/common/The Binding of Isaac Rebirth (nu)                     [.venv14]
[woc@nixos]> ./isaac.x64
Could not start dynamically linked executable: /home/woc/.local/share/Steam/steamapps/common/The Binding of Isaac Rebirth/isaac.x64
NixOS cannot run dynamically linked executables intended for generic
linux environments out of the box. For more information, see:
https://nix.dev/permalink/stub-ld

steamapps/common/The Binding of Isaac Rebirth (nu)                     [.venv14]
[woc@nixos]> cat run-x64.sh
#!/bin/sh
export LD_LIBRARY_PATH="lib64:$LD_LIBRARY_PATH"
exec "./isaac.x64" "$@"

steamapps/common/The Binding of Isaac Rebirth (nu)                     [.venv14]
[woc@nixos]> bash ./run-x64.sh
Could not start dynamically linked executable: ./isaac.x64
NixOS cannot run dynamically linked executables intended for generic
linux environments out of the box. For more information, see:
https://nix.dev/permalink/stub-ld
```

Well, in NixOS we cannot run it barely. Let's first do it in our fhs:

```
steamapps/common/The Binding of Isaac Rebirth (nu)                     [.venv14]
[woc@nixos]> fhs

steamapps/common/The Binding of Isaac Rebirth (bash|FHS)               [.venv14]
[woc@nixos]> ./run-x64.sh
./isaac.x64: error while loading shared libraries: libopenal.so.1: cannot open shared object file: No such file or directory
```

Oh, it hit me that maybe it is just due to lack of important libraries!

However, since this is a nearly bare fhs environment, it doesn't include some system libs we already installed in nixos. Here `libopenal.so.1` is the first missing lib in our fhs, but in fact our system already has it. So the real missing lib should be another one.

One way is continuously add lib packages in our fhs until crash logs repeal some libs hadn't been installed in our nixos config. Then try to add them one by one.

But lets try in another way: how does steam solve the "fhs" issue? Chatgpt told me that the steam-wrapper in NixOS will create a fhs environment. Then each game launched by it is a subprocess, then inherit its fhs environment. 

Lets check it:
```
~ (nu)                                                                 [.venv14]
[woc@nixos]> ll /run/current-system/sw/bin/steam
lrwxrwxrwx - root  1 Jan  1970 /run/current-system/sw/bin/steam -> /nix/store/m7kb7y57djf0g3wc1spw6rlzql5cnnxn-steam-1.0.0.85/bin/steam

~ (nu)                                                                 [.venv14]
[woc@nixos]> ll /nix/store/m7kb7y57djf0g3wc1spw6rlzql5cnnxn-steam-1.0.0.85/bin/steam
lrwxrwxrwx - root  1 Jan  1970 /nix/store/m7kb7y57djf0g3wc1spw6rlzql5cnnxn-steam-1.0.0.85/bin/steam -> /nix/store/mgp4akf1nj5f6dig5v5i0cmv767jxcaz-steam-1.0.0.85-bwrap

~ (nu)                                                                                                                                                     [.venv14]
[woc@nixos]> ll /nix/store/mgp4akf1nj5f6dig5v5i0cmv767jxcaz-steam-1.0.0.85-bwrap
.r-xr-xr-x 6.0k root  1 Jan  1970 /nix/store/mgp4akf1nj5f6dig5v5i0cmv767jxcaz-steam-1.0.0.85-bwrap
```

Oh, it is true. And fortunately it provide us with `steam-run` to launch a game, using fhs created by steam.

```
steamapps/common/The Binding of Isaac Rebirth (nu)                     [.venv14]
[woc@nixos]> steam-run ./run-x64.sh
./isaac.x64: error while loading shared libraries: libGLU.so.1: cannot open shared object file: No such file or directory
```

Ooops! `libGLU.so.1` is what we need. Since I am not sure if it is the only missing lib, I will use `nix-shell -p libGLU` to add it temporarily.

Executing nix-shell will give us a bash einvironment. We can use `nix eval` to locate the path it will installed in.

```
steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> nix eval --raw nixpkgs#libGLU.outPath
/nix/store/42nr5fc76c382kwjaj7dwwr39x5xi182-glu-9.0.3

steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> ls /nix/store/42nr5fc76c382kwjaj7dwwr39x5xi182-glu-9.0.3/lib/
libGLU.a  libGLU.so  libGLU.so.1  libGLU.so.1.3.1
```

Run it again:

```
steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> export LD_LIBRARY_PATH=/nix/store/42nr5fc76c382kwjaj7dwwr39x5xi182-glu-9.0.3/lib

steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> steam-run ./isaac.x64
./isaac.x64: error while loading shared libraries: libsteam_api.so: cannot open shared object file: No such file or directory
```

Ah, this time is `libsteam_api.so`. However, I soon identified that it is not included in any open packages. Instead, it should be installed by steam. 

Note that there has already been `lib32/64` in the game folder, let's dive into it.
```
steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> ls
isaac.i386  isaac.x64  lib32  lib64  resources  run-i386.sh  run-x64.sh  savedatapath.txt  tools

steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> ls lib64
libsteam_api.so
```

Add it to `LD_LIBRARY_PATH`:

```
steamapps/common/The Binding of Isaac Rebirth (bash)                                                                                                       [.venv14]
[woc@nixos]> export LD_LIBRARY_PATH="$(nix eval --raw nixpkgs#libGLU.outPath)/lib:$(pwd)/lib32:$(pwd)/lib64"
```

I think it is just an issue only occurred when we use `steam-run` manually. We should not need to solve it in our steam client. So what matters is only the `libGLU` package.

Sadly, this time we encounter the same crash log:

```
Stack trace of thread 28967:
#0  0x000000000054459d _ZN12EntityConfig11LoadPlayersEPKcb (isaac.x64 + 0x14459d)
#1  0x00000000007dcfd9 _ZN7Manager11LoadConfigsEv (isaac.x64 + 0x3dcfd9)
#2  0x00000000007dd8b5 _ZN7Manager4InitEv (isaac.x64 + 0x3dd8b5)
#3  0x000000000071fb02 _Z12IsaacStartupiPPc (isaac.x64 + 0x31fb02)
#4  0x00000000004ef0e6 main (isaac.x64 + 0xef0e6)
#5  0x000073ec1fa2b285 __libc_start_call_main (/nix/store/34dkjp1wxxh6djsvxk8nhvzp0izasds0-glibc-2.42-67/lib/libc.so.6 + 0x2b285)
#6  0x000073ec1fa2b338 __libc_start_main@@GLIBC_2.34 (/nix/store/34dkjp1wxxh6djsvxk8nhvzp0izasds0-glibc-2.42-67/lib/libc.so.6 + 0x2b338)
#7  0x00000000004f0891 _start (isaac.x64 + 0xf0891)
ELF object binary architecture: AMD x86-64
```

It is `EntityConfig::LoadPlayers(char const*, bool)`