---
title: NixOS-04 Constructing fhs in NixOS, and run ida pro
categories: [sys-note, NixOS]
tags: [system, nixos]
---

### Make a mini-fhs using buildFHSEnv
> [Running Downloaded Binaries on NixOS](https://nixos-and-flakes.thiscute.world/best-practices/run-downloaded-binaries-on-nixos)

We can add a custom package in our configuration.nix. Note that we add some GUI lib in `targetPkgs`. Otherwise it is a bare fhs containing some common libs.
```nix
environment = {
    systemPackages = with pkgs; [ 

      # Create FHS environment
      (let base = pkgs.appimageTools.defaultFhsEnvArgs; in
        pkgs.buildFHSEnv (base // {
        name = "fhs";
        targetPkgs = pkgs:
          # pkgs.buildFHSEnv provides only a minimal FHS environment,
          # lacking many basic packages needed by most software.
          # Therefore, we need to add them manually.
          #
          # pkgs.appimageTools provides basic packages required by most software.
          (base.targetPkgs pkgs) ++ (with pkgs; [
            pkg-config
            ncurses
            # Feel free to add more packages here if needed.
            # Qt runtime
            qt6.qtbase
            qt6.qtwayland
            qt6.qtsvg

            # Common GUI/runtime libs
            glib
            dbus
            fontconfig
            freetype
            libGL
            mesa
            
            # xrog
            xorg.libXext
            xorg.libXrender
            xorg.libxcb
            xorg.libXi
            xorg.libXcursor
            xorg.libXrandr
            xorg.libXfixes
            xorg.libxkbfile
            libxkbcommon

            # Qt xcb platform plugin dependencies
            libxcb
            libxcb-util
            libxcb-cursor
            libxcb-image
            libxcb-keysyms
            libxcb-render-util
            libxcb-wm

            # Often useful
            zlib
            openssl
            curl
            alsa-lib
            pulseaudio
          ]
        );
        profile = "export FHS=1";
        runScript = "bash";
        extraOutputsToInstall = ["dev"];
      }))

    ];
    variables.EDITOR = "vim";
  };
```
which will create a wrapper named `fhs`. We can use it to enter a mini-fhs environment:
```
~
❯ fhs

[woc@nixos:~]$ ls /usr/lib | head
alsa-lib
audit
bash
cairo
cmake
crt1.o
crti.o
crtn.o
cups
dbus-1.0
```

Then we can run compiled binary, like ida installer `ida-pro_92_x64linux.run`.

If our NixOS doesn't has that dir, then neither in the fhs environment. But the installer will still make it, where it should place ida directory. Unfortunately, once we leave the fhs, the opt would dieappear. 

The correct way is: create `/opt` directory **outside** the fhs, then running installer in fhs. It will keep the installed ida pro.

We can use ldd to check the ida binary just installed:
```
❯ cd /opt/ida9/

/opt/ida9 via 🐍 v3.13.12
❯ ldd ./ida
        linux-vdso.so.1 (0x0000729e50ce1000)
        libQt6PrintSupport.so.6 => /opt/ida9/./libQt6PrintSupport.so.6 (0x0000729e50c6e000)
        libQt6OpenGLWidgets.so.6 => /opt/ida9/./libQt6OpenGLWidgets.so.6 (0x0000729e50c5e000)
        libQt6Widgets.so.6 => /opt/ida9/./libQt6Widgets.so.6 (0x0000729e4fc00000)
        libQt6Svg.so.6 => /opt/ida9/./libQt6Svg.so.6 (0x0000729e4fb73000)
        libQt6OpenGL.so.6 => /opt/ida9/./libQt6OpenGL.so.6 (0x0000729e4fac9000)
        libQt6Gui.so.6 => /opt/ida9/./libQt6Gui.so.6 (0x0000729e4f000000)
        libQt6Xml.so.6 => /opt/ida9/./libQt6Xml.so.6 (0x0000729e50c2a000)
        libQt6DBus.so.6 => /opt/ida9/./libQt6DBus.so.6 (0x0000729e4ef2b000)
        libQt6Core.so.6 => /opt/ida9/./libQt6Core.so.6 (0x0000729e4e600000)
        libpthread.so.0 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib/libpthread.so.0 (0x0000729e50c25000)
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libida.so => /opt/ida9/./libida.so (0x0000729e4b000000)
        libstdc++.so.6 => not found
        libm.so.6 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib/libm.so.6 (0x0000729e4ee43000)
        libgcc_s.so.1 => /nix/store/fv5lgysa3hmf3l3dkkpwvndcg6xwhy8m-xgcc-14.3.0-libgcc/lib/libgcc_s.so.1 (0x0000729e50bf3000)
        libc.so.6 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib/libc.so.6 (0x0000729e4ac00000)
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libxkbcommon.so.0 => not found
        libstdc++.so.6 => not found
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libxkbcommon.so.0 => not found
        libstdc++.so.6 => not found
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libxkbcommon.so.0 => not found
        libstdc++.so.6 => not found
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libxkbcommon.so.0 => not found
        libz.so.1 => not found
        libstdc++.so.6 => not found
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libxkbcommon.so.0 => not found
        libstdc++.so.6 => not found
        libEGL.so.1 => not found
        libfontconfig.so.1 => not found
        libX11.so.6 => not found
        libdl.so.2 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib/libdl.so.2 (0x0000729e50be4000)
        libglib-2.0.so.0 => not found
        libxkbcommon.so.0 => not found
        libGLX.so.0 => not found
        libOpenGL.so.0 => not found
        libz.so.1 => not found
        libfreetype.so.6 => not found
        libgthread-2.0.so.0 => not found
        libstdc++.so.6 => not found
        libstdc++.so.6 => not found
        libdbus-1.so.3 => not found
        libstdc++.so.6 => not found
        libglib-2.0.so.0 => not found
        libz.so.1 => not found
        libgthread-2.0.so.0 => not found
        librt.so.1 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib/librt.so.1 (0x0000729e50bd9000)
        /lib64/ld-linux-x86-64.so.2 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib64/ld-linux-x86-64.so.2 (0x0000729e50ce3000)
        libstdc++.so.6 => not found
        libstdc++.so.6 => not found

/opt/ida9 via 🐍 v3.13.12
❯ fhs

[woc@nixos:/opt/ida9]$ ldd ./ida
        linux-vdso.so.1 (0x00007510abae5000)
        libQt6PrintSupport.so.6 => /opt/ida9/./libQt6PrintSupport.so.6 (0x00007510aba72000)
        libQt6OpenGLWidgets.so.6 => /opt/ida9/./libQt6OpenGLWidgets.so.6 (0x00007510aba62000)
        libQt6Widgets.so.6 => /opt/ida9/./libQt6Widgets.so.6 (0x00007510aaa00000)
        libQt6Svg.so.6 => /opt/ida9/./libQt6Svg.so.6 (0x00007510aa973000)
        libQt6OpenGL.so.6 => /opt/ida9/./libQt6OpenGL.so.6 (0x00007510aa8c9000)
        libQt6Gui.so.6 => /opt/ida9/./libQt6Gui.so.6 (0x00007510a9e00000)
        libQt6Xml.so.6 => /opt/ida9/./libQt6Xml.so.6 (0x00007510aba2e000)
        libQt6DBus.so.6 => /opt/ida9/./libQt6DBus.so.6 (0x00007510a9d2b000)
        libQt6Core.so.6 => /opt/ida9/./libQt6Core.so.6 (0x00007510a9400000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007510aba21000)
        libGLX.so.0 => /lib/libGLX.so.0 (0x00007510ab9eb000)
        libOpenGL.so.0 => /lib/libOpenGL.so.0 (0x00007510aa89c000)
        libida.so => /opt/ida9/./libida.so (0x00007510a5e00000)
        libstdc++.so.6 => /lib/libstdc++.so.6 (0x00007510a5a00000)
        libm.so.6 => /lib/libm.so.6 (0x00007510a9c43000)
        libgcc_s.so.1 => /lib/libgcc_s.so.1 (0x00007510a9c15000)
        libc.so.6 => /lib/libc.so.6 (0x00007510a5600000)
        libxkbcommon.so.0 => /lib/libxkbcommon.so.0 (0x00007510a9bba000)
        libz.so.1 => /lib/libz.so.1 (0x00007510aa87d000)
        libEGL.so.1 => /lib/libEGL.so.1 (0x00007510ab1ea000)
        libfontconfig.so.1 => /lib/libfontconfig.so.1 (0x00007510a9b6a000)
        libX11.so.6 => /lib/libX11.so.6 (0x00007510a5cb2000)
        libdl.so.2 => /lib/libdl.so.2 (0x00007510ab9e2000)
        libglib-2.0.so.0 => /lib/libglib-2.0.so.0 (0x00007510a589f000)
        libfreetype.so.6 => /lib/libfreetype.so.6 (0x00007510a552a000)
        libgthread-2.0.so.0 => /lib/libgthread-2.0.so.0 (0x00007510ab9dd000)
        libdbus-1.so.3 => /lib/libdbus-1.so.3 (0x00007510a5846000)
        librt.so.1 => /lib/librt.so.1 (0x00007510aa878000)
        /lib64/ld-linux-x86-64.so.2 => /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/lib64/ld-linux-x86-64.so.2 (0x00007510abae7000)
        libXext.so.6 => /nix/store/4s53fg7fq2las9cmbzrbklmhvsff6hq9-libxext-1.3.6/lib/libXext.so.6 (0x00007510a9b55000)
        libGLdispatch.so.0 => /nix/store/208r91rq2yr19cxqldvj8qf47bcvrxmq-libglvnd-1.7.0/lib/libGLdispatch.so.0 (0x00007510a5470000)
        libbz2.so.1 => /nix/store/c9gi6iyyki9z92gycdb13wbpjqxwsxis-bzip2-1.0.8/lib/libbz2.so.1 (0x00007510a9b41000)
        libpng16.so.16 => /nix/store/gbw7569byyqy1j019c54xsqfy1in809d-libpng-apng-1.6.56/lib/libpng16.so.16 (0x00007510a5c76000)
        libbrotlidec.so.1 => /nix/store/rdcds33gd7zgrfichjkvy6ycvyk8cfxk-brotli-1.1.0-lib/lib/libbrotlidec.so.1 (0x00007510a9b32000)
        libexpat.so.1 => /nix/store/dn34cing3fxa7j6pi29xrfxp2nrb0i3y-expat-2.7.5/lib/libexpat.so.1 (0x00007510a5817000)
        libxcb.so.1 => /nix/store/zh5kvj6piamiphmr1rsn7gl584pxlsc3-libxcb-1.17.0/lib/libxcb.so.1 (0x00007510a5444000)
        libpcre2-8.so.0 => /nix/store/nm1r86xxvj45gyqpxha74cddb3d28wzm-pcre2-10.46/lib/libpcre2-8.so.0 (0x00007510a5396000)
        libsystemd.so.0 => /nix/store/64qjwn4wvfnlcm5ja238m6i3mrk2q076-systemd-minimal-258.7/lib/libsystemd.so.0 (0x00007510a519e000)
        libbrotlicommon.so.1 => /nix/store/rdcds33gd7zgrfichjkvy6ycvyk8cfxk-brotli-1.1.0-lib/lib/libbrotlicommon.so.1 (0x00007510a517b000)
        libXau.so.6 => /nix/store/4b3shwnniwczc26303iwyzksd561459j-libxau-1.0.12/lib/libXau.so.6 (0x00007510a93fb000)
        libXdmcp.so.6 => /nix/store/7js4zydm9gf8xbhmzqr209jnip0qhx5l-libxdmcp-1.1.5/lib/libXdmcp.so.6 (0x00007510a93f3000)
        libcap.so.2 => /nix/store/l8i82aqwd8vqv57l00a69am93ylpbssz-libcap-2.77-lib/lib/libcap.so.2 (0x00007510a580a000)
```

### Add a wrapper for binary, and manage the .desktop
It is troublesome if we have to enter fhs, switching directory and type the executables name every time we need to launch it. 

Remember that we have made a wrapper named `fhs`, which contains `runScript = "bash"` ? We can take a step further, directly making a wrapper for our ida:

```nix
{ pkgs, ... }:

let
  base = pkgs.appimageTools.defaultFhsEnvArgs;

  Ida_FhsApp = pkgs.buildFHSEnv (base // {
    name = "ida9";
    targetPkgs = pkgs:
      (base.targetPkgs pkgs) ++ (with pkgs; [
        qt6.qtbase
        qt6.qtwayland
        qt6.qtsvg

        glib
        dbus
        fontconfig
        freetype
        libGL
        mesa
        libxkbcommon

        xorg.libX11
        xorg.libXext
        xorg.libXrender
        xorg.libXi
        xorg.libXcursor
        xorg.libXrandr
        xorg.libXfixes
        xorg.libxkbfile

        libxcb
        libxcb-util
        libxcb-cursor
        libxcb-image
        libxcb-keysyms
        libxcb-render-util
        libxcb-wm

        zlib
        openssl
        curl
        alsa-lib
        pulseaudio
      ]);

    # set environment, like QT_QPA_PLATFORM
    profile = ''
      export FHS=1
      export QT_QPA_PLATFORM=xcb
    '';

    runScript = pkgs.writeShellScript "run-ida9" ''
      cd /opt/ida9
      exec ./ida "$@"
    '';
  });

  Ida_FhsDesktop = pkgs.makeDesktopItem {
    name = "ida9";
    desktopName = "IDA Professional 9.2";
    exec = "${Ida_FhsApp}/bin/ida9 %F";
    icon = "/opt/ida9/appico.png";
    terminal = false;
    type = "Application";
    categories = [ "Development" "Debugger" ];
  };

in
{
  home.packages = [
    Ida_FhsApp
    Ida_FhsDesktop
  ];
}
```
It will create a runnable file named `ida9` in our system. 
```
~
❯ which ida9
╭───┬─────────┬─────────────────────────────────┬──────────╮
│ # │ command │              path               │   type   │
├───┼─────────┼─────────────────────────────────┼──────────┤
│ 0 │ ida9    │ /home/woc/.nix-profile/bin/ida9 │ external │
╰───┴─────────┴─────────────────────────────────┴──────────╯
```
When we run it, it will be started using  `Ida_FhsApp.runScript`. 

And the newly created `ida9` will be placed under our `"${Ida_FhsApp}/bin/ida9"`. The `.desktop` just launch it.

### How does fhs works?
Now lets dive deeper into it.
```
~
❯ ll /home/woc/.nix-profile/bin/ida9
lrwxrwxrwx - root  1 Jan  1970 /home/woc/.nix-profile/bin/ida9 -> /nix/store/qjhgbyv3nvwsx002hvc1vbxq8vk092bs-ida9/bin/ida9

~
❯ ll /nix/store/qjhgbyv3nvwsx002hvc1vbxq8vk092bs-ida9/bin/ida9
lrwxrwxrwx - root  1 Jan  1970 /nix/store/qjhgbyv3nvwsx002hvc1vbxq8vk092bs-ida9/bin/ida9 -> /nix/store/7sxn102000prbl63147aa1w31h3nw79y-ida9-bwrap

~
❯ ll /nix/store/7sxn102000prbl63147aa1In simple terms: it launches bubblewrap to create a temporary Linux filesystem view that looks more like a normal distro, then runs your command inside it.

w31h3nw79y-ida9-bwrap
.r-xr-xr-x 4.3k root  1 Jan  1970 /nix/store/7sxn102000prbl63147aa1w31h3nw79y-ida9-bwrap

~
❯ file /nix/store/7sxn102000prbl63147aa1w31h3nw79y-ida9-bwrap
/nix/store/7sxn102000prbl63147aa1w31h3nw79y-ida9-bwrap: a /nix/store/3hgg7pr65imdrifqqh3flg3arvkc2r22-bash-5.3p3/bin/bash script, ASCII text executable, with very long lines (414)
```

Now let's have a look at `/nix/store/7sxn102000prbl63147aa1w31h3nw79y-ida9-bwrap`

```shell
#!/nix/store/3hgg7pr65imdrifqqh3flg3arvkc2r22-bash-5.3p3/bin/bash
ignored=(/nix /dev /proc /etc )
ro_mounts=()
symlinks=()
etc_ignored=()

# loop through all entries of root in the fhs environment, except its /etc.
for i in /nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/*; do
  path="/${i##*/}"
  if [[ $path == '/etc' ]]; then
    :
  elif [[ -L $i ]]; then
    symlinks+=(--symlink "$(/nix/store/hqkszxk2c0cxvd04xa4gsaqs182dw8l2-coreutils-9.8/bin/readlink "$i")" "$path")
    ignored+=("$path")
  else
    ro_mounts+=(--ro-bind "$i" "$path")
    ignored+=("$path")
  fi
done

# loop through the entries of /etc in the fhs environment.
if [[ -d /nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/etc ]]; then
  for i in /nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/etc/*; do
    path="/${i##*/}"
    # NOTE: we're binding /etc/fonts and /etc/ssl/certs from the host so we
    # don't want to override it with a path from the FHS environment.
    if [[ $path == '/fonts' || $path == '/ssl' ]]; then
      continue
    fi
    if [[ -L $i ]]; then
      symlinks+=(--symlink "$i" "/etc$path")
    else
      ro_mounts+=(--ro-bind "$i" "/etc$path")
    fi
    etc_ignored+=("/etc$path")
  done
fi

# propagate /etc from the actual host if nested
if [[ -e /.host-etc ]]; then
  ro_mounts+=(--ro-bind /.host-etc /.host-etc)
else
  ro_mounts+=(--ro-bind /etc /.host-etc)
fi

# link selected etc entries from the actual root
for i in /etc/static /etc/nix /etc/shells /etc/bashrc /etc/zshenv /etc/zshrc /etc/zinputrc /etc/zprofile /etc/passwd /etc/group /etc/shadow /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/profiles /etc/login.defs /etc/sudoers /etc/sudoers.d /etc/localtime /etc/zoneinfo /etc/machine-id /etc/os-release /etc/pam.d /etc/fonts /etc/alsa /etc/asound.conf /etc/ssl/certs /etc/ca-certificates /etc/pki /etc/dconf; do
  if [[ "${etc_ignored[@]}" =~ "$i" ]]; then
    continue
  fi
  if [[ -e $i ]]; then
    symlinks+=(--symlink "/.host-etc/${i#/etc/}" "$i")
  fi
done

declare -a auto_mounts
# loop through all directories in the root
for dir in /*; do
  # if it is a directory and it is not ignored
  if [[ -d "$dir" ]] && [[ ! "${ignored[@]}" =~ "$dir" ]]; then
    # add it to the mount list
    auto_mounts+=(--bind "$dir" "$dir")
  fi
done

declare -a x11_args
# Always mount a tmpfs on /tmp/.X11-unix
# Rationale: https://github.com/flatpak/flatpak/blob/be2de97e862e5ca223da40a895e54e7bf24dbfb9/common/flatpak-run.c#L277
x11_args+=(--tmpfs /tmp/.X11-unix)

# Try to guess X socket path. This doesn't cover _everything_, but it covers some things.
if [[ "$DISPLAY" == *:* ]]; then
  # recover display number from $DISPLAY formatted [host]:num[.screen]
  display_nr=${DISPLAY/#*:} # strip host
  display_nr=${display_nr/%.*} # strip screen
  local_socket=/tmp/.X11-unix/X$display_nr
  x11_args+=(--ro-bind-try "$local_socket" "$local_socket")
fi

cmd=(
  /nix/store/zlr46rx9vymqip9fvjm2wc6hbba8ir8h-bubblewrap-0.11.0/bin/bwrap
  --dev-bind /dev /dev
  --proc /proc
  --chdir "$(pwd)"
  --die-with-parent
  --bind /nix /nix
  
  # Our glibc will look for the cache in its own path in `/nix/store`.
  # As such, we need a cache to exist there, because pressure-vessel
  # depends on the existence of an ld cache. However, adding one
  # globally proved to be a bad idea (see #100655), the solution we
  # settled on being mounting one via bwrap.
  # Also, the cache needs to go to both 32 and 64 bit glibcs, for games
  # of both architectures to work.
  --tmpfs /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc \
  --tmpfs /etc \
  --symlink /etc/ld.so.conf /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/ld.so.conf \
  --symlink /etc/ld.so.cache /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/ld.so.cache \
  --ro-bind /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/rpc /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/rpc \
  --remount-ro /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc \
  --symlink /nix/store/iaf4mxlfnqj834jb2xjdb54d1yqxs06v-ida9-init /init \
  "${ro_mounts[@]}"
  "${symlinks[@]}"
  "${auto_mounts[@]}"
  "${x11_args[@]}"
  
  /nix/store/0nsp0l4w0sng9s392pdq8cspv345cqv3-container-init "$@"
)
exec "${cmd[@]}"
```

Oh, it will likely make some links according to `/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/`. Interesting.

```
/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs🔒
❯ ll
lrwxrwxrwx - root  1 Jan  1970 bin -> /usr/bin
dr-xr-xr-x - root  1 Jan  1970 etc
lrwxrwxrwx - root  1 Jan  1970 lib -> /usr/lib
lrwxrwxrwx - root  1 Jan  1970 lib32 -> /usr/lib32
lrwxrwxrwx - root  1 Jan  1970 lib64 -> /usr/lib64
lrwxrwxrwx - root  1 Jan  1970 libexec -> /usr/libexec
dr-xr-xr-x - root  1 Jan  1970 nix-support
lrwxrwxrwx - root  1 Jan  1970 sbin -> /usr/sbin
dr-xr-xr-x - root  1 Jan  1970 usr

/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs🔒
❯ l etc/
bash_completion.d  e2scrub.conf  locale      mke2fs.conf  pkcs11     profile.d  rpc       systemd            xdg
cups               fonts         login.defs  mtab         pkgconfig  protocols  services  vdpau_wrapper.cfg  xinetd.d
dbus-1             gtk-3.0       man         pam.d        profile    pulse      ssl       X11                xkeyboard-config-2

/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs🔒
❯ ll usr
dr-xr-xr-x - root  1 Jan  1970 bin
dr-xr-xr-x - root  1 Jan  1970 include
lrwxrwxrwx - root  1 Jan  1970 lib -> /usr/lib64
dr-xr-xr-x - root  1 Jan  1970 lib64
dr-xr-xr-x - root  1 Jan  1970 libexec
dr-xr-xr-x - root  1 Jan  1970 sbin
dr-xr-xr-x - root  1 Jan  1970 share

/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs🔒
❯ ll usr/bin/ | head
lrwxrwxrwx - root  1 Jan  1970 [ -> /nix/store/hqkszxk2c0cxvd04xa4gsaqs182dw8l2-coreutils-9.8/bin/[
lrwxrwxrwx - root  1 Jan  1970 addpart -> /nix/store/yk67hi22z3sfc0dnd3qckpkpf3h2i8bx-util-linux-minimal-2.41.4-bin/bin/addpart
lrwxrwxrwx - root  1 Jan  1970 agetty -> /nix/store/yk67hi22z3sfc0dnd3qckpkpf3h2i8bx-util-linux-minimal-2.41.4-bin/bin/agetty
lrwxrwxrwx - root  1 Jan  1970 amdgpu_stress -> /nix/store/fzlr5v7m3smp01ph2kcwi1r39xrmpg6g-libdrm-2.4.129-bin/bin/amdgpu_stress
lrwxrwxrwx - root  1 Jan  1970 androiddeployqt -> /nix/store/244my2zgxwabmj007911x6rj6g4095c5-qtbase-6.10.2/bin/androiddeployqt
lrwxrwxrwx - root  1 Jan  1970 androiddeployqt6 -> /nix/store/244my2zgxwabmj007911x6rj6g4095c5-qtbase-6.10.2/bin/androiddeployqt6
lrwxrwxrwx - root  1 Jan  1970 androidtestrunner -> /nix/store/244my2zgxwabmj007911x6rj6g4095c5-qtbase-6.10.2/bin/androidtestrunner
lrwxrwxrwx - root  1 Jan  1970 aserver -> /nix/store/r5zzvqh6393pgz2nzqya4ihx73mjgb49-alsa-lib-1.2.14/bin/aserver
lrwxrwxrwx - root  1 Jan  1970 awk -> /nix/store/88d79vz87a5g3wsclabrgqd93jqh5yv8-gawk-5.3.2/bin/awk
lrwxrwxrwx - root  1 Jan  1970 b2sum -> /nix/store/hqkszxk2c0cxvd04xa4gsaqs182dw8l2-coreutils-9.8/bin/b2sum

/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs🔒
❯ ll etc/pulse/
lrwxrwxrwx - root  1 Jan  1970 client.conf -> /nix/store/26a6cj4pnf1ssz736wf176rqlfd6hc22-pulseaudio-17.0/etc/pulse/client.conf
lrwxrwxrwx - root  1 Jan  1970 daemon.conf -> /nix/store/26a6cj4pnf1ssz736wf176rqlfd6hc22-pulseaudio-17.0/etc/pulse/daemon.conf
lrwxrwxrwx - root  1 Jan  1970 default.pa -> /nix/store/26a6cj4pnf1ssz736wf176rqlfd6hc22-pulseaudio-17.0/etc/pulse/default.pa
lrwxrwxrwx - root  1 Jan  1970 system.pa -> /nix/store/26a6cj4pnf1ssz736wf176rqlfd6hc22-pulseaudio-17.0/etc/pulse/systsem.pa
```

Now we know how does the `buildFHSEnv` work. It will first create a base rootfs, including our needed packages & config files. (But they are links, won't take too much space.)

#### Step1: common dirs & files
```shell
# loop through all entries of root in the fhs environment, except its /etc.
for i in /nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/*; do
  path="/${i##*/}"
  if [[ $path == '/etc' ]]; then
    :
  elif [[ -L $i ]]; then
    symlinks+=(--symlink "$(/nix/store/hqkszxk2c0cxvd04xa4gsaqs182dw8l2-coreutils-9.8/bin/readlink "$i")" "$path")
    ignored+=("$path")
  else
    ro_mounts+=(--ro-bind "$i" "$path")
    ignored+=("$path")
  fi
done
```
The `path="/${i##*/}"` will remove everything up to the last `/`.
Then comes appending to symlinks array. Finally, 
```
/nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/bin -> /usr/bin
```
would be
```
/bin -> /usr/bin
```

You may be confused: since the binary in /usr/bin is actually linked to `/nix/...`, after chroot, will it be broken? In fact, the `/nix` dir is also included, so everything is fine.
```
--bind /nix /nix
```

#### Step2: link /etc
Since our NixOS also use `/etc` as config directory, it doesn't directly link the whole `/etc`.

It will begin with selected /etc files in rootfs template.
```shell
# loop through the entries of /etc in the fhs environment.
if [[ -d /nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/etc ]]; then
  for i in /nix/store/n733pvvf4nh1spgsfxwx1qbhj0qgb2p2-ida9-fhsenv-rootfs/etc/*; do
    path="/${i##*/}"
    # NOTE: we're binding /etc/fonts and /etc/ssl/certs from the host so we
    # don't want to override it with a path from the FHS environment.
    if [[ $path == '/fonts' || $path == '/ssl' ]]; then
      continue
    fi
    if [[ -L $i ]]; then
      symlinks+=(--symlink "$i" "/etc$path")
    else
      ro_mounts+=(--ro-bind "$i" "/etc$path")
    fi
    etc_ignored+=("/etc$path")
  done
fi
```
Then some other files, like `/etc/passwd`
```shell
# link selected etc entries from the actual root
for i in /etc/static /etc/nix /etc/shells /etc/bashrc /etc/zshenv /etc/zshrc /etc/zinputrc /etc/zprofile /etc/passwd /etc/group /etc/shadow /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/profiles /etc/login.defs /etc/sudoers /etc/sudoers.d /etc/localtime /etc/zoneinfo /etc/machine-id /etc/os-release /etc/pam.d /etc/fonts /etc/alsa /etc/asound.conf /etc/ssl/certs /etc/ca-certificates /etc/pki /etc/dconf; do
  if [[ "${etc_ignored[@]}" =~ "$i" ]]; then
    continue
  fi
  if [[ -e $i ]]; then
    symlinks+=(--symlink "/.host-etc/${i#/etc/}" "$i")
  fi
done
```

The following lines will link the `/etc` in NixOS to `/.host-etc` in FHS.
```shell
# propagate /etc from the actual host if nested
if [[ -e /.host-etc ]]; then
  ro_mounts+=(--ro-bind /.host-etc /.host-etc)
else
  ro_mounts+=(--ro-bind /etc /.host-etc)
fi
```

#### Step3: mount other dir
It will add other directories under `/` to fhs, if not in ignored list.
```shell
declare -a auto_mounts
# loop through all directories in the root
for dir in /*; do
  # if it is a directory and it is not ignored
  if [[ -d "$dir" ]] && [[ ! "${ignored[@]}" =~ "$dir" ]]; then
    # add it to the mount list
    auto_mounts+=(--bind "$dir" "$dir")
  fi
done
```
That's why our created `/opt` will appear in fhs environment.


#### Step4: build container with `bwrap`
```shell
cmd=(
  /nix/store/zlr46rx9vymqip9fvjm2wc6hbba8ir8h-bubblewrap-0.11.0/bin/bwrap
  --dev-bind /dev /dev
  --proc /proc
  --chdir "$(pwd)"
  --die-with-parent
  --bind /nix /nix
  
  # Our glibc will look for the cache in its own path in `/nix/store`.
  # As such, we need a cache to exist there, because pressure-vessel
  # depends on the existence of an ld cache. However, adding one
  # globally proved to be a bad idea (see #100655), the solution we
  # settled on being mounting one via bwrap.
  # Also, the cache needs to go to both 32 and 64 bit glibcs, for games
  # of both architectures to work.
  --tmpfs /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc \
  --tmpfs /etc \
  --symlink /etc/ld.so.conf /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/ld.so.conf \
  --symlink /etc/ld.so.cache /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/ld.so.cache \
  --ro-bind /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/rpc /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/rpc \
  --remount-ro /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc \
  --symlink /nix/store/iaf4mxlfnqj834jb2xjdb54d1yqxs06v-ida9-init /init \
  "${ro_mounts[@]}"
  "${symlinks[@]}"
  "${auto_mounts[@]}"
  "${x11_args[@]}"
  
  /nix/store/0nsp0l4w0sng9s392pdq8cspv345cqv3-container-init "$@"
)
exec "${cmd[@]}"
```

The last line
```shell
exec "${cmd[@]}"
```
will replace the current shell process with our defined command, that is `bwrap` and `container-init` 
> `@` is a special character used to represent all members of a collection.
> 
{: .prompt-info}

BubbleWrap is a tool for creating a lightweight container using Linux namespaces.

- bind file
`--dev-bind /dev /dev` exposes the real host /dev inside the environment.

- new file
`--proc /proc` create a new /proc inside the fhs.

- chroot
`--chdir "$(pwd)"` changes root.

- etc
Then comes /etc tricks:
```
--tmpfs /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc \
--tmpfs /etc \
--symlink /etc/ld.so.conf /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/ld.so.conf \
--symlink /etc/ld.so.cache /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/ld.so.cache \
--ro-bind /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/rpc /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc/rpc \
--remount-ro /nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224/etc
```
`--tmpfs /etc` creates a tmpfs. In built fhs, it has:
```
/nix/store/...-glibc.../etc/ld.so.conf  -> /etc/ld.so.conf
/nix/store/...-glibc.../etc/ld.so.cache -> /etc/ld.so.cache
```
> **What is tmpfs**
> Files in tmpfs live in RAM/swap, not on a normal disk. Files disappear when the tmpfs is unmounted or the system reboots.
{: .prompt-info}

- init file
`--symlink /nix/store/iaf4mxlfnqj834jb2xjdb54d1yqxs06v-ida9-init /init \` will links the init script.

now `/nix/store/iaf4mxlfnqj834jb2xjdb54d1yqxs06v-ida9-init`:
```shell
#!/nix/store/3hgg7pr65imdrifqqh3flg3arvkc2r22-bash-5.3p3/bin/bash
source /etc/profile
exec /nix/store/brvw4vxjibhkg6vdmkkgrhf6w2nzgy4x-run-ida9 "$@"
```
good, good, these two lines will set environment variables, and launch program.

Lets first look into `/nix/store/brvw4vxjibhkg6vdmkkgrhf6w2nzgy4x-run-ida9`:
```shell
#!/nix/store/3hgg7pr65imdrifqqh3flg3arvkc2r22-bash-5.3p3/bin/bash
cd /opt/ida9
exec ./ida "$@"
```
which is exactly our `runScript`.

Then the `/etc/profile`. but we must realize that it is working under fhs environment. so we should find its source, which turned out to be `etc/profile` under rootfs.
```shell
export PS1='ida9-fhsenv:\u@\h:\w\$ '
export LOCALE_ARCHIVE="${LOCALE_ARCHIVE:-/usr/lib/locale/locale-archive}"
export PATH="/run/wrappers/bin:/usr/bin:/usr/sbin:$PATH"
export TZDIR='/etc/zoneinfo'

# XDG_DATA_DIRS is used by pressure-vessel (steam proton) and vulkan loaders to find the corresponding icd
export XDG_DATA_DIRS=$XDG_DATA_DIRS${XDG_DATA_DIRS:+:}/run/opengl-driver/share:/run/opengl-driver-32/share

# Following XDG spec [1], XDG_DATA_DIRS should default to "/usr/local/share:/usr/share".
# In nix, it is commonly set without containing these values, so we add them as fallback.
#
# [1] <https://specifications.freedesktop.org/basedir-spec/latest>
case ":$XDG_DATA_DIRS:" in
  *:/usr/local/share:*) ;;
  *) export XDG_DATA_DIRS="$XDG_DATA_DIRS${XDG_DATA_DIRS:+:}/usr/local/share" ;;
esac
case ":$XDG_DATA_DIRS:" in
  *:/usr/share:*) ;;
  *) export XDG_DATA_DIRS="$XDG_DATA_DIRS${XDG_DATA_DIRS:+:}/usr/share" ;;
esac

# Force compilers and other tools to look in default search paths
unset NIX_ENFORCE_PURITY
export NIX_BINTOOLS_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu=1
export NIX_CC_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu=1
export NIX_CFLAGS_COMPILE="-idirafter /usr/include"${NIX_CFLAGS_COMPILE:+" $NIX_CFLAGS_COMPILE"}
export NIX_CFLAGS_LINK="-L/usr/lib -L/usr/lib32"${NIX_CFLAGS_LINK:+" $NIX_CFLAGS_LINK"}
export NIX_LDFLAGS="-L/usr/lib -L/usr/lib32"${NIX_LDFLAGS:+" $NIX_LDFLAGS"}
export PKG_CONFIG_PATH=/usr/lib/pkgconfig${PKG_CONFIG_PATH:+":$PKG_CONFIG_PATH"}
export ACLOCAL_PATH=/usr/share/aclocal${ACLOCAL_PATH:+":$ACLOCAL_PATH"}

# GStreamer searches for plugins relative to its real binary's location
# https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/bd97973ce0f2c5495bcda5cccd4f7ef7dcb7febc
export GST_PLUGIN_SYSTEM_PATH_1_0=/usr/lib/gstreamer-1.0:/usr/lib32/gstreamer-1.0${GST_PLUGIN_SYSTEM_PATH_1_0:+":$GST_PLUGIN_SYSTEM_PATH_1_0"}

export FHS=1
export QT_QPA_PLATFORM=xcb
```
Interesting! We finally find variables `FHS` and `QT_QPA_PLATFORM` in this init file

- other args
Finally add our prepared args:
```shell
  "${ro_mounts[@]}"
  "${symlinks[@]}"
  "${auto_mounts[@]}"
  "${x11_args[@]}"
```

#### Step5: final launch
Now lets come back to bwrap. Its command format is:
```
bwrap [sandbox options...] COMMAND [ARGS...]
```
So the container-init in the end
```shell
  /nix/store/0nsp0l4w0sng9s392pdq8cspv345cqv3-container-init "$@"
```
is indeed the `COMMAND` of bwrap.


To sum up, the execution is like:
```
your wrapper script
  -> bwrap ...
      -> container-init "$@"
          -> /init
              -> export/set env vars
              -> exec runScript "$@"
```
