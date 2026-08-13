---
title: Run & Check cross-platform binary in NixOS
categories: [note, nixos]
tags: [note, system]
---

As my NixOS is growing into a "usable" system step by step, I am working hard on learning "the way" to finish those tasks that can be done on normal FHS-distros naturally. The first one for me is the ctf toolchains.

Frankly, I didn't feel any inconvenience when installing normal tools including `ghidra`, `pwndbg`, etc. They have mostly been added in nixpkgs. 

One exception is `ida-pro`, since it is not a free software. I have to use the certain binary working perfectly on other linux distros, while needs a little hacking on our NixOS. But in fact we just need to make a simple fhs environment containing libraries used by it (like qt), and wrap it again to make it easy to launch. I did it in my previous post: NixOS-04 Constructing fhs in NixOS, and run ida pro[](https://9vvert.github.io/posts/nixos-use-fhs-ida/). I also explored how does the "fhs" work in NixOS on earth.

My current experience tells that the biggest challenge to running some binaries normally in NixOS comes from it doesn adhere to `FHS`. This time let's step further, to explore how to run a binary with different arch, and with specified libs version.

### 0x01 How to run a 32bit binary

Yes, our first step is to launch a 32bit x86 ELF in NixOS-64bit, even it is as simple as breathing in normal linux distros.

Here let's check a 32-bit binary:

```
~/ctf/test (zsh)
[woc@nixos]> checksec ./bof
[*] '/home/woc/ctf/test/bof'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

~/ctf/test (zsh)
[woc@nixos]> ldd ./bof
        not a dynamic executable
```

In normal system, we have both the `/lib/ld-linux.so.2` and `/lib64/ld-linux-x86-64.so.2`. So when running a binary, it will choose the correct one (according to the ld info contained in ELF binary)

However the 64bit NixOS **DOESN'T** provide `/lib/ld-linux.so.2` by default. That's why we couldn't launch it, and also neither `ldd` (which is based on `ld`).

Fortunately there is a tool named `nix-ld` to fix it.

```nix
environment.systemPackages = with pkgs; [
   # the 'programs.nix-ld.enable = true' is enough. this only add a runnable nix-ld command to path
   nix-ld
];

programs.nix-ld = {
   enable = true;
   libraries = with pkgs; [
      # some libs
      ...
   ];
};
```

> https://wiki.nixos.org/wiki/Nix-ld

Let's check our system again after rebuilding.

```
~/ctf/test (zsh)
[woc@nixos]> ll /lib/ld-linux.so.2
lrwxrwxrwx - root  3 Aug 15:44 /lib/ld-linux.so.2 -> /nix/store/4lg3391g2x2m87nnmpadw4i027z106g6-nix-ld-2.0.6/libexec/nix-ld

~/ctf/test (zsh)
[woc@nixos]> ll /lib64/ld-linux-x86-64.so.2
lrwxrwxrwx - root  3 Aug 14:44 /lib64/ld-linux-x86-64.so.2 -> /nix/store/3jbxih2a7hpq5d6a0ng4j8fnrancsnw8-nix-ld-2.0.6/libexec/nix-ld
```

Good! This creates `/lib`. Note that those two ld points to different `nix-ld`. It is because they are different architecture (32 & 64 bit) builds of the same nix-ld version.

In fact `ldd` works similarly to `ld --library-path <path> --list <binary>`. For 32bit binary, we need to use the "right ld" and "right lib path" - `"$NIX_LD_i686_linux" --library-path "$NIX_LD_LIBRARY_PATH_i686_linux" --list "$@"`. We can wrap it into a tool:

```nix
environment.systemPackages = with pkgs; [
   # ldd for 32bit binary
   (pkgs.writeShellScriptBin "ldd32" ''
   "$NIX_LD_i686_linux" \
   --library-path "$NIX_LD_LIBRARY_PATH_i686_linux" \
   --list "$@"
   '')
];

# Provide the FHS interpreter requested by 32-bit x86 ELF binaries.
# The normal nix-ld module only installs the x86-64 interpreter.
environment.ldso32 = "${pkgs.pkgsi686Linux.nix-ld}/libexec/nix-ld";
environment.sessionVariables = {
   NIX_LD_i686_linux = pkgs.pkgsi686Linux.stdenv.cc.bintools.dynamicLinker;
   NIX_LD_LIBRARY_PATH_i686_linux = "${pkgs.pkgsi686Linux.glibc}/lib";
};
```

Now run with `ldd32`:

```
~/ctf/test (zsh)
[woc@nixos]> ldd32 ./bof
        linux-gate.so.1 (0xeeafa000)
        libc.so.6 => /nix/store/g6z25558pyfwriw4fhc104hj7xrr4ain-glibc-2.42-67/lib/libc.so.6 (0xee8ad000)
        /lib/ld-linux.so.2 => /nix/store/g6z25558pyfwriw4fhc104hj7xrr4ain-glibc-2.42-67/lib/ld-linux.so.2 (0xeeafc000)
```

> linux-gate.so.1 is the 32-bit x86 vDSO: a small ELF shared object generated and mapped into the process by the Linux kernel at execution time. Our ldd info shows is mapped at 0xeeafa000. 
>
> The 64bit equivalent is normally "linux-vdso.so.1"
{: .prompt-info }

### 0x02 How to run a binary from different arch

#### Cross-platform GNU gcc/g++ toolchains

Now lets try to launch an arm64 ELF.

After installing `qemu`, we now have `qemu-aarch64`.

```
~/ctf (zsh)
[woc@nixos]> readelf -h ./koori
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0xcc0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          65832 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         26
  Section header string table index: 25
```

But we cannot run it currently:
```
~/ctf (zsh)
[woc@nixos]> qemu-aarch64 ./koori
qemu-aarch64: Could not open '/lib/ld-linux-aarch64.so.1': No such file or directory
```

It is because our qemu won't provide ld/libc for cross-platform. We need to install them manually:

```nix
environment = {
    systemPackages = [
      # ARM 32-bit Linux, hard-float
      pkgsCross.armv7l-hf-multiplatform.stdenv.cc

      # ARM 64-bit Linux
      pkgsCross.aarch64-multiplatform.stdenv.cc

      # RISC-V 32-bit Linux
      pkgsCross.riscv32.stdenv.cc

      # RISC-V 64-bit Linux
      pkgsCross.riscv64.stdenv.cc
    ];
  };
```

Generally, GNU C/C++ toolchains contains something like this:

- GNU compiler (gcc, g++), and their runtime dependency libs

- GNU binutils (as, ld, objdump, ...)

- GNU c/c++ standard libs 
  The `libc.so.6` is usually in glibc package. While the `libstdc++.so.6` is contained in gcc-toolchain.

Let's take arm64 (also called aarch64) as an example. It has a few builds: 


1. Compiler: `stdenv.cc.cc.outPath`

```sh
~/nixos-config <dev!> (zsh)
[woc@nixos]> nix eval --raw '.#nixosConfigurations.nixos.pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc.cc.outPath'
warning: Git tree '/home/woc/nixos-config' is dirty
/nix/store/002fr50b02rcpc46zx1vxq0q7y2mp4ds-aarch64-unknown-linux-gnu-gcc-15.2.0

~/nixos-config <dev!> (zsh)
[woc@nixos]> ls /nix/store/002fr50b02rcpc46zx1vxq0q7y2mp4ds-aarch64-unknown-linux-gnu-gcc-15.2.0
aarch64-unknown-linux-gnu  bin  include  lib  libexec  nix-support  share
```

It provodied some compiler-related tools like `gcc`, `g++`:

```
~ (zsh)
[woc@nixos]> ls -l /nix/store/002fr50b02rcpc46zx1vxq0q7y2mp4ds-aarch64-unknown-linux-gnu-gcc-15.2.0/bin
total 59988
-r-xr-xr-x 1 root root  2384624 Jan  1  1970 aarch64-unknown-linux-gnu-c++
-r-xr-xr-x 1 root root  2384592 Jan  1  1970 aarch64-unknown-linux-gnu-cpp
-r-xr-xr-x 1 root root  2384624 Jan  1  1970 aarch64-unknown-linux-gnu-g++
-r-xr-xr-x 1 root root  2380448 Jan  1  1970 aarch64-unknown-linux-gnu-gcc
-r-xr-xr-x 1 root root  2380448 Jan  1  1970 aarch64-unknown-linux-gnu-gcc-15.2.0
-r-xr-xr-x 1 root root    46184 Jan  1  1970 aarch64-unknown-linux-gnu-gcc-ar
-r-xr-xr-x 1 root root    46184 Jan  1  1970 aarch64-unknown-linux-gnu-gcc-nm
-r-xr-xr-x 1 root root    46184 Jan  1  1970 aarch64-unknown-linux-gnu-gcc-ranlib
-r-xr-xr-x 1 root root  1683520 Jan  1  1970 aarch64-unknown-linux-gnu-gcov
-r-xr-xr-x 1 root root  1472536 Jan  1  1970 aarch64-unknown-linux-gnu-gcov-dump
-r-xr-xr-x 1 root root  1498104 Jan  1  1970 aarch64-unknown-linux-gnu-gcov-tool
-r-xr-xr-x 1 root root 44685656 Jan  1  1970 aarch64-unknown-linux-gnu-lto-dump
```

2. Compiler runtime lib: `stdenv.cc.cc.lib.outPath`, also provided c++ lib

```sh
~/nixos-config <dev!> (zsh)
[woc@nixos]> nix eval --raw '.#nixosConfigurations.nixos.pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc.cc.lib.outPath'
warning: Git tree '/home/woc/nixos-config' is dirty
/nix/store/aqmjs0bsc5k80q7gh85yf5xfdv6kblwl-aarch64-unknown-linux-gnu-gcc-15.2.0-lib

~/nixos-config <dev!> (zsh)
[woc@nixos]> ls /nix/store/aqmjs0bsc5k80q7gh85yf5xfdv6kblwl-aarch64-unknown-linux-gnu-gcc-15.2.0-lib
aarch64-unknown-linux-gnu  lib  share
```

This is gcc's seperate runtime-library output, including `libgcc_s.so`, `libstdc++.so.6`, which are indispensable when running c++ compiled binaries. 

```
~/nixos-config <dev!> (zsh)
[woc@nixos]> ls /nix/store/aqmjs0bsc5k80q7gh85yf5xfdv6kblwl-aarch64-unknown-linux-gnu-gcc-15.2.0-lib/aarch64-unknown-linux-gnu/lib/
libasan.so        libatomic.so.1.2.0  libgomp.so.1.0.0    libitm.so.1       libssp.so        libstdc++.so.6.0.34         libubsan.so
libasan.so.8      libgcc_s.so         libhwasan.so        libitm.so.1.0.0   libssp.so.0      libstdc++.so.6.0.34-gdb.py  libubsan.so.1
libasan.so.8.0.0  libgcc_s.so.1       libhwasan.so.0      liblsan.so        libssp.so.0.0.0  libtsan.so                  libubsan.so.1.0.0
libatomic.so      libgomp.so          libhwasan.so.0.0.0  liblsan.so.0      libstdc++.so     libtsan.so.2
libatomic.so.1    libgomp.so.1        libitm.so           liblsan.so.0.0.0  libstdc++.so.6   libtsan.so.2.0.0
```


3. Glibc and dynamic loader: `stdenv.cc.libc.outPath`

```sh
~/nixos-config <dev!> (zsh)
[woc@nixos]> nix eval --raw '.#nixosConfigurations.nixos.pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc.libc.outPath'
warning: Git tree '/home/woc/nixos-config' is dirty
/nix/store/r45mhvfylc16wdbi91q4v4mwifprw818-glibc-aarch64-unknown-linux-gnu-2.42-67

~/nixos-config <dev!> (zsh)
[woc@nixos]> ls /nix/store/r45mhvfylc16wdbi91q4v4mwifprw818-glibc-aarch64-unknown-linux-gnu-2.42-67
etc  lib  lib64  libexec  share
```

This is the target glibc, including `libc.so.6`, `libm.so.6`, `libdl.so.2`, and dynamic loader `ld-linux-aarch64.so.1`.

```
~ (zsh)
[woc@nixos]> ls /nix/store/r45mhvfylc16wdbi91q4v4mwifprw818-glibc-aarch64-unknown-linux-gnu-2.42-67/lib
audit    grcrt1.o               libc_malloc_debug.so    libdl.so.2      libnsl.so.1         libnss_files.so.2   libresolv.so       libutil.so
crt1.o   ld-linux-aarch64.so.1  libc_malloc_debug.so.0  libmemusage.so  libnss_compat.so    libnss_hesiod.so    libresolv.so.2     libutil.so.1
crti.o   libanl.so              libc_nonshared.a        libm.so         libnss_compat.so.2  libnss_hesiod.so.2  librt.so           locale
crtn.o   libanl.so.1            libc.so                 libm.so.6       libnss_db.so        libpcprofile.so     librt.so.1         Mcrt1.o
gconv    libBrokenLocale.so     libc.so.6               libmvec.so      libnss_db.so.2      libpthread.so       libthread_db.so    rcrt1.o
gcrt1.o  libBrokenLocale.so.1   libdl.so                libmvec.so.1    libnss_dns.so.2     libpthread.so.0     libthread_db.so.1  Scrt1.o
```


4. Binutils: `stdenv.cc.bintools.outPath`

```sh
~/nixos-config <dev!> (zsh)
[woc@nixos]> nix eval --raw '.#nixosConfigurations.nixos.pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc.bintools.outPath'
warning: Git tree '/home/woc/nixos-config' is dirty
/nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46

~/nixos-config <dev!> (zsh)
[woc@nixos]> ls /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46
bin  nix-support
```

This is nix binutils wrapper, including `aarch64-unknown-linux-gnu-ld`, `aarch64-unknown-linux-gnu-as`,  `aarch64-unknown-linux-gnu-ar`, `aarch64-unknown-linux-gnu-objdump`, `aarch64-unknown-linux-gnu-readelf`, etc.

```
~ (zsh)
[woc@nixos]> ls -l /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin
total 96
lrwxrwxrwx 1 root root   123 Jan  1  1970 aarch64-unknown-linux-gnu-addr2line -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-addr2line
lrwxrwxrwx 1 root root   116 Jan  1  1970 aarch64-unknown-linux-gnu-ar -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-ar
lrwxrwxrwx 1 root root   116 Jan  1  1970 aarch64-unknown-linux-gnu-as -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-as
lrwxrwxrwx 1 root root   121 Jan  1  1970 aarch64-unknown-linux-gnu-c++filt -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-c++filt
lrwxrwxrwx 1 root root   117 Jan  1  1970 aarch64-unknown-linux-gnu-dwp -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-dwp
lrwxrwxrwx 1 root root   121 Jan  1  1970 aarch64-unknown-linux-gnu-elfedit -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-elfedit
lrwxrwxrwx 1 root root   119 Jan  1  1970 aarch64-unknown-linux-gnu-gprof -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-gprof
-r-xr-xr-x 1 root root 12018 Jan  1  1970 aarch64-unknown-linux-gnu-ld
-r-xr-xr-x 1 root root 12042 Jan  1  1970 aarch64-unknown-linux-gnu-ld.bfd
-r-xr-xr-x 1 root root 12048 Jan  1  1970 aarch64-unknown-linux-gnu-ld.gold
lrwxrwxrwx 1 root root   116 Jan  1  1970 aarch64-unknown-linux-gnu-nm -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-nm
lrwxrwxrwx 1 root root   121 Jan  1  1970 aarch64-unknown-linux-gnu-objcopy -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-objcopy
lrwxrwxrwx 1 root root   121 Jan  1  1970 aarch64-unknown-linux-gnu-objdump -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-objdump
lrwxrwxrwx 1 root root   120 Jan  1  1970 aarch64-unknown-linux-gnu-ranlib -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-ranlib
lrwxrwxrwx 1 root root   121 Jan  1  1970 aarch64-unknown-linux-gnu-readelf -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-readelf
lrwxrwxrwx 1 root root   118 Jan  1  1970 aarch64-unknown-linux-gnu-size -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-size
lrwxrwxrwx 1 root root   121 Jan  1  1970 aarch64-unknown-linux-gnu-strings -> /nix/store/0p2p894mrhxihq7gk88z7dc258pkii21-aarch64-unknown-linux-gnu-binutils-2.46/bin/aarch64-unknown-linux-gnu-strings
-r-xr-xr-x 1 root root   254 Jan  1  1970 aarch64-unknown-linux-gnu-strip
```

> Wait... There is one `aarch64-unknown-linux-gnu-ld`. But we have already seen one `ld-linux-aarch64.so.1` in glibc pkg. What's their difference?
> 
> In fact, `aarch64-unknown-linux-gnu-ld` works during compilation, to link different obj file. While `ld-linux-aarch64.so.1` is a dynamic loader, also called "ELF interpreter". 
> 
> In compiling step, interpreter path is set in `INTERP` section.
> 
> ```
> ~ (zsh)
> [woc@nixos]> readelf -l /home/woc/.nix-profile/bin/ghostty
> 
> Elf file type is DYN (Position-Independent Executable file)
> Entry point 0x11b0
> There are 13 program headers, starting at offset 64
> 
> Program Headers:
>   Type           Offset             VirtAddr           PhysAddr
>                  FileSiz            MemSiz              Flags  Align
>   PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
>                  0x00000000000002d8 0x00000000000002d8  R      0x8
>   INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
>                  0x0000000000000053 0x0000000000000053  R      0x1
>       [Requesting program interpreter: /nix/store/34dkjp1wxxh6djsvxk8nhvzp0izasds0-glibc-2.42-67/lib/ld-linux-x86-64.so.2]
> ......
> ```
>
> Binaries in NixOS has an interpreter pinned to ld-linux-x86-64.so.2 with the certain version.
>
{: .prompt-info }


1. Full binary path `stdenv.cc.outPath`

```sh
~/nixos-config <dev!> (zsh)
[woc@nixos]> nix eval --raw '.#nixosConfigurations.nixos.pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc.outPath'
warning: Git tree '/home/woc/nixos-config' is dirty
/nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0

~/nixos-config <dev!> (zsh)
[woc@nixos]> ls /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0
bin  nix-support
```

Here we have both compiler gcc/g++ and binutils.

```
~ (zsh)
[woc@nixos]> ls -l /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/bin
total 116
lrwxrwxrwx 1 root root   131 Jan  1  1970 aarch64-unknown-linux-gnu-addr2line -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-addr2line
lrwxrwxrwx 1 root root   124 Jan  1  1970 aarch64-unknown-linux-gnu-ar -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-ar
lrwxrwxrwx 1 root root   124 Jan  1  1970 aarch64-unknown-linux-gnu-as -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-as
lrwxrwxrwx 1 root root    29 Jan  1  1970 aarch64-unknown-linux-gnu-c++ -> aarch64-unknown-linux-gnu-g++
lrwxrwxrwx 1 root root    29 Jan  1  1970 aarch64-unknown-linux-gnu-cc -> aarch64-unknown-linux-gnu-gcc
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-c++filt -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-c++filt
-r-xr-xr-x 1 root root 11462 Jan  1  1970 aarch64-unknown-linux-gnu-cpp
lrwxrwxrwx 1 root root   125 Jan  1  1970 aarch64-unknown-linux-gnu-dwp -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-dwp
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-elfedit -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-elfedit
-r-xr-xr-x 1 root root 11462 Jan  1  1970 aarch64-unknown-linux-gnu-g++
-r-xr-xr-x 1 root root 11462 Jan  1  1970 aarch64-unknown-linux-gnu-gcc
lrwxrwxrwx 1 root root   127 Jan  1  1970 aarch64-unknown-linux-gnu-gprof -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-gprof
lrwxrwxrwx 1 root root   124 Jan  1  1970 aarch64-unknown-linux-gnu-ld -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-ld
lrwxrwxrwx 1 root root   128 Jan  1  1970 aarch64-unknown-linux-gnu-ld.bfd -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-ld.bfd
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-ld.gold -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-ld.gold
lrwxrwxrwx 1 root root   124 Jan  1  1970 aarch64-unknown-linux-gnu-nm -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-nm
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-objcopy -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-objcopy
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-objdump -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-objdump
lrwxrwxrwx 1 root root   128 Jan  1  1970 aarch64-unknown-linux-gnu-ranlib -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-ranlib
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-readelf -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-readelf
lrwxrwxrwx 1 root root   126 Jan  1  1970 aarch64-unknown-linux-gnu-size -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-size
lrwxrwxrwx 1 root root   129 Jan  1  1970 aarch64-unknown-linux-gnu-strings -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-strings
lrwxrwxrwx 1 root root   127 Jan  1  1970 aarch64-unknown-linux-gnu-strip -> /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin/aarch64-unknown-linux-gnu-strip
```

If look closely, you may notice that there are `aarch64-unknown-linux-gnu-gcc` and `aarch64-unknown-linux-gnu-g++`, which have already been shown in `stdenv.cc.cc.outPath`, except for their different size.

```
~ (zsh)
[woc@nixos]> file /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-gnu-gcc
/nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-gnu-gcc: a /nix/store/fmmhdx9k95s8iqag7zip533mbl3f27sw-bash-5.3p9/bin/bash script, ASCII text executable
```

Oh, the gcc and g++ here are both an ascii script "wrapper". What's more, the `aarch64-unknown-linux-gnu-ld` and many more binutils here points to gnu-binutils-wrapper. Shortly, this is a top level package with all files are wrapper(or linked to a wrapper) that refer to previous builds.

```
stdenv.cc.outPath:
   gcc/g++  ---wrapper---> stdenv.cc.cc.outPath
   binutils -----link----> stdenv.cc.bintools.outPath ---wrapper---> real-binutils
```

#### Preliminary exploration of the "cc-wrapper"

Focus on the following lines:

```sh
# Flirting with a layer violation here.
if [ -z "${NIX_BINTOOLS_WRAPPER_FLAGS_SET_aarch64_unknown_linux_gnu:-}" ]; then
    source /nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/nix-support/add-flags.sh
fi

# Put this one second so libc ldflags take priority.
if [ -z "${NIX_CC_WRAPPER_FLAGS_SET_aarch64_unknown_linux_gnu:-}" ]; then
    source /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/add-flags.sh
fi
```

> \[ -z STRING_VAR \] is used to test if it is empty string
>
> `${VAR:-}` means: if `VAR` has been set and not null, then eval it. otherwise set it to empty string.
{: .prompt-info }

The `nix-support` directory is generated based on nixpkgs's `pkgs/build-support/cc-wrapper/default.nix`, it has:

```
~ (zsh)
[woc@nixos]> ls /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/
add-flags.sh      cc-cflags         cc-ldflags             dynamic-linker  libc-crt1-cflags  libcxx-cxxflags  orig-cc    orig-libc-dev            setup-hook
add-hardening.sh  cc-cflags-before  darwin-sdk-setup.bash  libc-cflags     libc-ldflags      libcxx-ldflags   orig-libc  propagated-build-inputs  utils.bash
```

Then check `add-flag.sh`:

```sh
# N.B. It may be a surprise that the derivation-specific variables are exported,
# since this is just sourced by the wrapped binaries---the end consumers. This
# is because one wrapper binary may invoke another (e.g. cc invoking ld). In
# that case, it is cheaper/better to not repeat this step and let the forked
# wrapped binary just inherit the work of the forker's wrapper script.

var_templates_list=(
    NIX_CFLAGS_COMPILE
    NIX_CFLAGS_COMPILE_BEFORE
    NIX_CFLAGS_LINK
    NIX_CXXSTDLIB_COMPILE
    NIX_CXXSTDLIB_LINK
    NIX_GNATFLAGS_COMPILE
)
var_templates_bool=(
    NIX_ENFORCE_NO_NATIVE
)

accumulateRoles

# We need to mangle names for hygiene, but also take parameters/overrides
# from the environment.
for var in "${var_templates_list[@]}"; do
    mangleVarList "$var" ${role_suffixes[@]+"${role_suffixes[@]}"}
done
for var in "${var_templates_bool[@]}"; do
    mangleVarBool "$var" ${role_suffixes[@]+"${role_suffixes[@]}"}
done

# Prepending `/nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin' to $PATH forces cc to use ld-wrapper.sh when calling ld.
# $path_backup is where cc-wrapper.sh stores the $PATH that will be used for the
# compiler invocation.
path_backup="/nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin:$path_backup"

# Export and assign separately in order that a failing $(..) will fail
# the script.

# Currently bootstrap-tools does not split glibc, and gcc files into
# separate directories. As a workaround we want resulting cflags to be
# ordered as: crt1-cflags libc-cflags cc-cflags. Otherwise we mix crt/libc.so
# from different libc as seen in
#   https://github.com/NixOS/nixpkgs/issues/158042
#
# Note that below has reverse ordering as we prepend flags one-by-one.
# Once bootstrap-tools is split into different directories we can stop
# relying on flag ordering below.

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags ]; then
    NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu="$(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags) $NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu"
fi

if [[ "$cInclude" = 1 ]] && [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libc-cflags ]; then
    NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu="$(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libc-cflags) $NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu"
fi

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libc-crt1-cflags ]; then
    NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu="$(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libc-crt1-cflags) $NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu"
fi

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libcxx-cxxflags ]; then
    NIX_CXXSTDLIB_COMPILE_aarch64_unknown_linux_gnu+=" $(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libcxx-cxxflags)"
fi

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libcxx-ldflags ]; then
    NIX_CXXSTDLIB_LINK_aarch64_unknown_linux_gnu+=" $(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libcxx-ldflags)"
fi

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/gnat-cflags ]; then
    NIX_GNATFLAGS_COMPILE_aarch64_unknown_linux_gnu="$(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/gnat-cflags) $NIX_GNATFLAGS_COMPILE_aarch64_unknown_linux_gnu"
fi

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-ldflags ]; then
    NIX_LDFLAGS_aarch64_unknown_linux_gnu+=" $(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-ldflags)"
fi

if [ -e /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags-before ]; then
    NIX_CFLAGS_COMPILE_BEFORE_aarch64_unknown_linux_gnu="$(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags-before) $NIX_CFLAGS_COMPILE_BEFORE_aarch64_unknown_linux_gnu"
fi

# Only add darwin min version flag if a default darwin min version is set,
# which is a signal that we're targetting darwin.
if [ "" ]; then
    mangleVarSingle  ${role_suffixes[@]+"${role_suffixes[@]}"}

    NIX_CFLAGS_COMPILE_BEFORE_aarch64_unknown_linux_gnu="-m-version-min=${_aarch64_unknown_linux_gnu:-} $NIX_CFLAGS_COMPILE_BEFORE_aarch64_unknown_linux_gnu"
fi

# That way forked processes will not extend these environment variables again.
export NIX_CC_WRAPPER_FLAGS_SET_aarch64_unknown_linux_gnu=1
```

It sets a path containing binutils:

```
path_backup="/nix/store/m5nywlaz9j9n8ph5gyaprs2wvz904f3f-aarch64-unknown-linux-gnu-binutils-wrapper-2.46/bin:$path_backup"
```

This appends new args to current `NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu`.
```sh
NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu="$(< /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags) $NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu"
```

> `$(< file_path)` means read file content in bash. similar to `$(cat file_path)`
{: .prompt-info }

Okay, lets then inspect those flag files one by one.

```
# gcc toolchain lib, with libstdc++.so, etc -> NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu
~ (zsh)
[woc@nixos]> cat /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags
-B/nix/store/aqmjs0bsc5k80q7gh85yf5xfdv6kblwl-aarch64-unknown-linux-gnu-gcc-15.2.0-lib/aarch64-unknown-linux-gnu/lib 


# aarch64 glibc headers, with stdio.h, etc -> NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu
~ (zsh)
[woc@nixos]> cat /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libc-cflags
-idirafter /nix/store/vwc81q7k5xm9zshmhhqvw33v5vv3033y-glibc-aarch64-unknown-linux-gnu-2.42-67-dev/include -idirafter /nix/store/002fr50b02rcpc46zx1vxq0q7y2mp4ds-aarch64-unknown-linux-gnu-gcc-15.2.0/lib/gcc/aarch64-unknown-linux-gnu/15.2.0/include-fixed

# Startup objects, with libc.so.6, crt1.o, etc -> NIX_CFLAGS_COMPILE_aarch64_unknown_linux_gnu
# This lets gcc find Scrt1.o, crt1.o, crti.o, crtn.o
~ (zsh)
[woc@nixos]> cat /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/libc-crt1-cflags
-B/nix/store/r45mhvfylc16wdbi91q4v4mwifprw818-glibc-aarch64-unknown-linux-gnu-2.42-67/lib/ 

# Target CPU flags -> NIX_CFLAGS_COMPILE_BEFORE_aarch64_unknown_linux_gnu
~ (zsh)
[woc@nixos]> cat /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-cflags-before
-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -march=armv8-a

# gcc runtime linker directory (the same as cc-cflags)
~/nixos-config <dev!> (zsh)
[woc@nixos]> cat /nix/store/5bifwnfhbbclblypsmrafy4lrq3x0fya-aarch64-unknown-linux-gnu-gcc-wrapper-15.2.0/nix-support/cc-ldflags
-L/nix/store/aqmjs0bsc5k80q7gh85yf5xfdv6kblwl-aarch64-unknown-liEintf "%q\n" \
       ${extraBefore+"${extraBefore[@]}"} \
       ${params+"${params[@]}"} \
       ${extraAfter+"${extraAfter[@]}"} > "$responseFile"
    /nix/store/002fr50b02rcpc46zx1vxq0q7y2mp4ds-aarch64-unknown-linux-gnu-gcc-15.2.0/bin/aarch64-unknown-linux-gnu-gcc "@$responseFile"
else
    exec /nix/store/002fr50b02rcpc46zx1vxq0q7y2mp4ds-aarch64-unknown-linux-gnu-gcc-15.2.0/bin/aarch64-unknown-linux-gnu-gcc \
       ${extraBefore+"${extraBefore[@]}"} \
       ${params+"${params[@]}"} \
       ${extraAfter+"${extraAfter[@]}"}
fi
```

Finally it calls the real gcc with our prepared args, to enable it working normally.

#### Run with qemu

Add some env vars for convenience:

```nix
{ pkgs, inputs, ... }:
let
  aarch64_cross = pkgs.pkgsCross.aarch64-multiplatform;
  aarch64_prefix = aarch64_cross.stdenv.cc.targetPrefix;

  aarch32_cross = pkgs.pkgsCross.armv7l-hf-multiplatform;
  aarch32_prefix = aarch32_cross.stdenv.cc.targetPrefix;

  riscv64_cross = pkgs.pkgsCross.riscv64;
  riscv64_prefix = riscv64_cross.stdenv.cc.targetPrefix;

  riscv32_cross = pkgs.pkgsCross.riscv32;
  riscv32_prefix = riscv32_cross.stdenv.cc.targetPrefix;
in
{
  environment = {
    systemPackages = [
      # ARM 64-bit Linux
      aarch64_cross.stdenv.cc
      # ARM 32-bit Linux, hard-float
      aarch32_cross.stdenv.cc
      # RISC-V 64-bit Linux
      riscv64_cross.stdenv.cc
      # RISC-V 32-bit Linux
      riscv32_cross.stdenv.cc
    ];

    sessionVariables = {
      AARCH64_BIN = "${aarch64_cross.stdenv.cc}/bin";
      AARCH64_LIBC = "${aarch64_cross.stdenv.cc.libc}";
      AARCH64_INTERP = "${aarch64_cross.stdenv.cc.libc}/lib/ld-linux-aarch64.so.1";
      AARCH64_GCC_LIB = "${aarch64_cross.stdenv.cc.cc.lib}";

      AARCH32_BIN = "${aarch32_cross.stdenv.cc}/bin";
      AARCH32_LIBC = "${aarch32_cross.stdenv.cc.libc}";
      AARCH32_INTERP = "${aarch32_cross.stdenv.cc.libc}/lib/ld-linux-armhf.so.3";
      AARCH32_GCC_LIB = "${aarch32_cross.stdenv.cc.cc.lib}";

      RISCV64_BIN = "${riscv64_cross.stdenv.cc}/bin";
      RISCV64_LIBC = "${riscv64_cross.stdenv.cc.libc}";
      RISCV64_INTERP = "${riscv64_cross.stdenv.cc.libc}/lib/ld-linux-riscv64-lp64d.so.1";
      RISCV64_GCC_LIB = "${riscv64_cross.stdenv.cc.cc.lib}";

      RISCV32_BIN = "${riscv32_cross.stdenv.cc}/bin";
      RISCV32_LIBC = "${riscv32_cross.stdenv.cc.libc}";
      RISCV32_INTERP = "${riscv32_cross.stdenv.cc.libc}/lib/ld-linux-riscv32-ilp32d.so.1";
      RISCV32_GCC_LIB = "${riscv32_cross.stdenv.cc.cc.lib}";
    };
  };
}
```

- `AARCH64_BIN`:
   has some binutils.
- `AARCH64_LIBC` :
   root of glibc. the libs are placed in `$AARCH64_LIBC/lib`.
- `AARCH64_INTERP`:
   dynamic loader.
- `AARCH64_GCC_LIB`:
   root of gcc lib. the libs are placed in `$AARCH64_GCC_LIB/lib`.


Now we can run it with `-L`, which specify the guest filesystem root:

```
~/ctf (zsh)
[woc@nixos]> qemu-aarch64 -L $AARCH64_LIBC ./koori
Please send your input :) abcdef
Your input has been validated :D
```
