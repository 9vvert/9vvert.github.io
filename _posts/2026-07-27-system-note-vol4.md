---
title: System Misc Note - Vol4
categories: [note, system]
tags: [note, system]
---

### Use journalctl to inspect daemon log
After restarting my dae service, I suddenly found that my network was corrupted. Even `ping 8.8.8.8` would fail with "ping: connect: Network is unreachable".

Test with:
```
$ ip -4 route get 8.8.8.8
RTNETLINK answers: Network is unreachable
```

Use `nmcli device show` to inspect current net status. It is stranged that I dont have `IP4.ADDRESS` here:

```
$ nmcli device show
GENERAL.DEVICE:                         wlp0s20f3
GENERAL.TYPE:                           wifi
GENERAL.HWADDR:                         5C:B4:7E:8D:69:FE
GENERAL.MTU:                            1500
GENERAL.STATE:                          100 (connected)
GENERAL.CONNECTION:                     Tsinghua-IPv4
GENERAL.CON-PATH:                       /org/freedesktop/NetworkManager/ActiveC>
IP4.GATEWAY:                            --
IP6.ADDRESS[1]:                         2402:f000:5:7801:49e7:7d3f:635a:a9e2/64
IP6.ADDRESS[2]:                         2402:f000:5:7801:a3ff:72f2:d328:45b2/64
IP6.ADDRESS[3]:                         fe80::8a1f:d204:3f0a:efeb/64
IP6.GATEWAY:                            fe80::9e74:6fff:fe9f:d001
IP6.ROUTE[1]:                           dst = fe80::/64, nh = ::, mt = 1024
IP6.ROUTE[2]:                           dst = 2402:f000:5:7801::/64, nh = ::, m>
IP6.ROUTE[3]:                           dst = ::/0, nh = fe80::9e74:6fff:fe9f:d>
IP6.DNS[1]:                             2402:f000:1:801::8:28
IP6.DNS[2]:                             2402:f000:1:801::8:29

GENERAL.DEVICE:                         lo
GENERAL.TYPE:                           loopback
GENERAL.HWADDR:                         00:00:00:00:00:00
GENERAL.MTU:                            65536
GENERAL.STATE:                          100 (connected (externally))
GENERAL.CONNECTION:                     lo
GENERAL.CON-PATH:                       /org/freedesktop/NetworkManager/ActiveC>
IP4.ADDRESS[1]:                         127.0.0.1/8
IP4.GATEWAY:                            --
IP6.ADDRESS[1]:                         ::1/128
IP6.GATEWAY:                            --

......

GENERAL.DEVICE:                         dae0
```

Well, althougn still confused, I strongly suepect it was caused by dae service. Then use `journalctl -b -u dae --no-pager | less` to check log:

```
...
Jul 27 00:12:04 nixos dae[2858]: level=fatal msg="duplicated outbound name: common_proxy"
Jul 27 00:12:04 nixos systemd[1]: dae.service: Main process exited, code=exited, status=1/FAILURE
Jul 27 00:12:04 nixos systemd[1]: dae.service: Failed with result 'exit-code'.
Jul 27 00:12:04 nixos systemd[1]: Failed to start dae Service.
Jul 27 00:12:04 nixos systemd[1]: dae.service: Consumed 582ms CPU time, 153.8M memory peak, 31.6M read from disk, 2.5K incoming IP traffic, 1.1K outgoing IP traffic.
...
```

> **journalctl command**
>
> -f  , follow new logs live
>
> -b  , only see logs during this boot
>
> -u \<name\> , view logs for specific service
>
> --since \<time\> , filter by time. like: `since today`, `since "1 hour ago"`, `--since "2026-06-01 00:00:00" --until "2026-06-01 12:00:00"` 
{: .prompt-info }


Ah... it is just because of wrong config file. After fixing it and rebooting, everything is back to normal.

### Set 'prefer-no-csd' of niri
After I install `Prism Launcher` and started playing minecraft, it came out that there was always a disturbing bar at top, and the bottom of origin window was crowded out of screen.

![](/assets/img/2026/minecraft_topbar.png)

At first I use niri's `mod + shift + f` to make it fullscreen. It only works temporarily, however. Once I click some button in the game, the fucking top bar appears again.

Use `niri msg windows` to inspect. After niri fullscreen:
```
Window ID 85:
  Title: "Minecraft 26.2 - Singleplayer"
  App ID: "Minecraft 26.2"
  Is floating: no
  PID: 1493
  Workspace ID: 1
  Layout:
    Tile size: 1536 x 960
    Scrolling position: column 5, tile 1
    Window size: 1536 x 960
    Window offset in tile: 0 x 0
```

After click a button in game:
```
Window ID 85:
  Title: "Minecraft 26.2 - Singleplayer"
  App ID: "Minecraft 26.2"
  Is floating: no
  PID: 1493
  Workspace ID: 1
  Layout:
    Tile size: 1536 x 984.80
    Scrolling position: column 5, tile 1
    Window size: 1536 x 985
    Window offset in tile: 0 x 0
```

Okay, obviously there were extra 25px after click event, which caused niri to re-calculate window size. 

The solution is: turn on `prefer-no-csd` in niri. (In NixOS, it is `programs.niri.settings.prefer-no-csd = true`).

But note that the change of niri often needs logout & login again to take effect. Then the top bar is finally gone. Gooooood!

### coredumpctl

When encountering program crash, we can use `coredumpctl` to view log.

```
coredumpctl list --since "2026-07-30 12:06:30"
```

Check the real log (optional: `--no-page`):

```
coredumpctl info isaac.x64
coredumpctl info <pid>
```

### config vscode in nixos

We can use `programs.vscode.profiles.default` to manage extensions and userSettings.

```nix
{pkgs, inputs, lib, ...}:

{
  programs.vscode = {
    enable = true;
    profiles.default={
      extensions = with pkgs.vscode-extensions; [
        dracula-theme.theme-dracula
        yzhang.markdown-all-in-one
      ];

      userSettings = {
        "window.restoreWindows" = "none";
        "[python]" = {
          "diffEditor.ignoreTrimWhitespace" = false;
          "editor.defaultColorDecorators" = "never";
        };
      };
    };
  };


}
```

But this will report below info during build:

```
Please do one of the following:
- In standalone mode, use 'home-manager switch -b backup' to back up files automatically.
- When used as a NixOS or nix-darwin module, set either
  - 'home-manager.backupFileExtension', or
  - 'home-manager.backupCommand',
  to move the file to a new location in the same directory, or run a custom command.
- Set 'force = true' on the related file options to forcefully overwrite the files below. eg. 'xdg.configFile."mimeapps.list".force = true'
Existing file '/home/woc/.config/Code/User/settings.json' would be clobbered
```

- try1

```nix
  # xdg.configFile is like home.file.".config"
  xdg.configFile."Code/User/settings.json" = {
    force = true;
  };

  # # Or the following way:
  # xdg.configFile."Code/User/settings.json".force = lib.mkForce true;
```

output:
```
  error: The option `xdg.configFile."Code/User/settings.json".source' was accessed but has no value defined. Try setting the option.
```

Once we check the src of vscode nix module, we will find that it just defines `home.file`. 

```nix
# home-manager/blob/master/modules/programs/vscode/mkVscodeModule.nix
  home.file = lib.mkMerge (
    ......
  )
```

Even if `xdg.confgFile` points to the same dir as `home.file.".config"`, they are not merged during build. 

So the fact is, we barely make an isolated file option, without setting neither its text nor source:

```
xdg.configFile."Code/User/settings.json" = {
  force = true;
};
```

> ## file-management in nixos
>
> ### file surffix
>
> 1. environment.etc."myfile" is `/etc/myfile`
>
> 2. home.file."myfile" is `/etc/myfile`
>
> 3. xdg.configFile."myfile" is `~/.config/myfile`
>
> ### file content
>
> 1. text
>
> ```
> xdg.configFile."myapp/config".text = ''
>   foo = bar
> '';
> ```
>
> 2. src
>
> home.file.".config/foo".source = ./foo;
{: .prompt-info }


- try2:

What about trying `home.file` ?

```nix
  home.file.".config/Code/User/settings.json" = lib.mkForce {
    force = true;
  };
```

output:
```
error:
Failed assertions:
- Conflicting managed target files: .config/Code/User/settings.json

This may happen, for example, if you have a configuration similar to

    home.file = {
      conflict1 = { source = ./foo.nix; target = "baz"; };
      conflict2 = { source = ./bar.nix; target = "baz"; };
    }       error:
Failed assertions:
- Conflicting managed target files: .config/Code/User/settings.json

This may happen, for example, if you have a configuration similar to

    home.file = {
      conflict1 = { source = ./foo.nix; target = "baz"; };
      conflict2 = { source = ./bar.nix; target = "baz"; };
    }
```

> ## What is lib.mkForce
> We can add some value after `lib.mkForce`, which means "When activating, overwrite an existing filesystem file > instead of refusing because it would be clobbered."
> 
> Example:
> 
> ```nix
> programs.foo.enable = lib.mkForce true;
> ```
{: .prompt-info }



You may think: since we use lib.mkForce to declare using our 'force', there shouldn't be any problem.

However, that is not the case. 

First, What we set with priority is not the attribute 'force', but the whole file option! That is, our file is defined in two place. 

Second, check the vscode nix module:
```nix
  userDir =
    if pkgs.stdenv.hostPlatform.isDarwin then
      "${config.home.homeDirectory}/Library/Application Support/${nameShort}/User"
    else
      "${config.xdg.configHome}/${nameShort}/User";     

  profileDir = name: "${userDir}${optionalString (name != "default") "/profiles/${name}"}";
  configFilePath = name: "${profileDir name}/settings.json";
  tasksFilePath = name: "${profileDir name}/tasks.json";
  ......
  home.file = lib.mkMerge (flatten [
      (mkIf (cfg.argvSettings != { }) {
        "${argvPath}".source =
          if isPathLike cfg.argvSettings then
            cfg.argvSettings
          else
            jsonFormat.generate "vscode-argv" cfg.argvSettings;
      })

      (mapAttrsToList (n: v: [
        (
          let
            merged = mergedUserSettings v.userSettings v.enableUpdateCheck v.enableExtensionUpdateCheck;
          in
          mkIf (merged != { }) {
            "${configFilePath n}".source =
              if isPathLike merged then merged else jsonFormat.generate "vscode-user-settings" merged;
          }
        )

        (mkIf (v.userTasks != { }) {
          "${tasksFilePath n}".source =
            if isPathLike v.userTasks then v.userTasks else jsonFormat.generate "vscode-user-tasks" v.userTasks;
        })

        ......
      )
    )
    ......
```
It only sets `home.file.".config/Code/User/settings.json"`'s `source`, so our `lib.mkForce force` won't take effect.

- try3

Now we finally figure out what does `lib.mkForce` really do - not the meaning of "overwrite and merge", but "when they merge, use this one with priority".

Remember that nix module will "automatically merge" some attributes at some case, can we just set `home.file.".config/Code/User/settings.json".force = true;` ?

Unfortunatelly it still fails with conflict error.

It is because in vscode nix module, the file path is calculated by a serial of functions. Although it eventually points to the same file, they are not viewed as two parts that can be merged.



**SUMMARY**

Now come back to the initial warning. It comes from an already existing `settings.json`, because it is my first time using nix module to generate its settings.json. 

So a direct solution is: check that file, migrate and then delete it.

### Fix Touchpad 
There was a time when my touchpad was disabled.

Use `libinput` to check devices:

```
...
Device:                  Intel HID events
Kernel:                  /dev/input/event3
Id:                      host:0000:0000
Group:                   6
Seat:                    seat0, default
Capabilities:            keyboard
Tap-to-click:            n/a
Tap-and-drag:            n/a
Tap button map:          n/a
Tap drag lock:           n/a
Left-handed:             n/a
Nat.scrolling:           n/a
Middle emulation:        n/a
Calibration:             n/a
Scroll methods:          none
Scroll button:           n/a
Scroll button lock:      n/a
Click methods:           none
Clickfinger button map:  n/a
Disable-w-typing:        n/a
Disable-w-trackpointing: n/a
Accel profiles:          n/a
Rotation:                0.0
Area rectangle:          n/a
...
```

Use `journalctl -b` to check log during this boot:

```
> journalctl -b | grep -iE 'touchpad|libinput|i2c|hid'
Sep 14 11:11:42 nixos kernel: hid: raw HID events driver (C) Jiri Kosina
Sep 14 11:11:42 nixos kernel: usbcore: registered new interface driver usbhid
Sep 14 11:11:42 nixos kernel: usbhid: USB HID core driver
Sep 14 11:11:42 nixos kernel: hid-generic 0003:1C4F:0034.0001: input,hidraw0: USB HID v1.10 Mouse [SIGMACHIP Usb Mouse] on usb-0000:00:14.0-4/input0
Sep 14 11:11:45 nixos kernel: input: Intel HID events as /devices/platform/INTC1070:00/input/input3
Sep 14 11:11:45 nixos kernel: intel-hid INTC1070:00: platform supports 5 button array
Sep 14 11:11:45 nixos kernel: input: Intel HID 5 button array as /devices/platform/INTC1070:00/input/input4
Sep 14 11:11:45 nixos kernel: i2c i2c-0: Successfully instantiated SPD at 0x50
Sep 14 11:11:45 nixos kernel: i2c_hid_acpi i2c-FTCS0038:00: unexpected HID descriptor bcdVersion (0x7878)
Sep 14 11:11:45 nixos kernel: i2c_hid_acpi i2c-FTCS0038:00: Failed to fetch the HID Descriptor
Sep 14 11:11:46 nixos systemd-logind[840]: Watching system buttons on /dev/input/event3 (Intel HID events)
Sep 14 11:11:46 nixos systemd-logind[840]: Watching system buttons on /dev/input/event4 (Intel HID 5 button array)
Sep 14 11:26:33 nixos sudo[10391]:      woc : TTY=pts/1 ; PWD=/home/woc/nixos-config ; USER=root ; COMMAND=/nix/store/h75hn4mbiz92khw1iqc8ymfyfh0j4fsy-libinput-1.31.3-bin/bin/libinput list-devices
```

Google "Failed to fetch the HID Descriptor" and find one solution: shutdown with power button. 

> https://forum.manjaro.org/t/touchpad-not-detected-i2c-hid-acpi-i2c-msft0001-failed-to-fetch-the-hid-descriptor/119311

I have tried reboot command before, which didn't fix the issue. But this new method worked.