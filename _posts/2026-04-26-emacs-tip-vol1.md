---
title: Emacs in nixos 101 - (1) Install and Basic Setting
categories: [note, NixOS]
tags: [emacs, tool]
---

### 0x01 Installing emacs in NixOS
Use the home-manager：
```nix
{inputs, pkgs, ...}:

{
  programs.emacs = {
    enable = true;
    package = pkgs.emacs-pgtk;
  };
}
```
I choose the `emacs-gtk`，rather than `emacs`, whose UI is in a vintage style.

### 0x02 Basic settings
Add `extraConfig` attribute to include some emacs settings, like indent-width and some file behavior.
```nix
{inputs, pkgs, ...}:

{
  programs.emacs = {
    enable = true;
    package = pkgs.emacs-gtk;  
    
    extraConfig = ''
      (setq inhibit-startup-screen t)   ; disable welcom message
      (setq standard-indent 2)
      (setq make-backup-files nil)      ; disable xxx.txt~ 
      (setq auto-save-default nil)      ; disable #xxx.txt#
      (global-display-line-numbers-mode 1)  ; enable line number
    '';
  };
}
```
So after rebuilding, the next time we launch emacs, we can use `C-h v` to check the info of a variable.

> **Fix eamcs window behavior in niri**
> You may need to add those settings if using niri
> ```elisp
> ; fix emacs window behavior in niri (https://github.com/niri-wm/niri/issues/2632)
> 
> (setopt frame-inhibit-implied-resize t)
>
> (setopt frame-resize-pixelwise t)
> ```
{: prompt-tip }

> **inline-help**
> 
> C-h k <key>: Describe Key. Shows the documentation for the command bound to a specific key sequence (e.g., C-h k C-f).
> 
> C-h f: Describe Function. Prompts for a function name and displays its documentation.
> 
> C-h v: Describe Variable. Shows the documentation and current value of a Lisp variable.
> 
> C-h a <string>: Apropos. Lists all commands whose names match a specific string or regular expression.
> 
> C-h t: Tutorial. Launches the interactive "learn-by-doing" Emacs tutorial.
> 
> C-h m: Mode Help. Describes the current major and minor modes and their specific key bindings.
>
> C-h C-h: Displays a comprehensive menu of all available help options.
{: .prompt-info }

TODO