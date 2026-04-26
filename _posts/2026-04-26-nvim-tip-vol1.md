---
title: Nvim diary - Lsp, and... mason?
categories: [system, nvim]
tags: [vim, tool]
---

我的nvim配置入门框架是照抄的nvim-kickstart这个项目，后来随着装的插件渐渐变多，开始逐渐拆分成自己的配置文件. 但是lsp的配置在我的nvim-config中一直处于遗留下来的屎山状态。最近在安装ocaml lsp的时候，遇到了无法正确安装的问题，决心真正去学习一下相关的配置原理.

### layer1: 原生nvim lsp
nvim提供了lsp client相关的api:
```lua
vim.lsp.buf.definition()
vim.lsp.buf.references()
vim.lsp.buf.hover()
vim.lsp.buf.rename()
vim.lsp.buf.code_action()
vim.lsp.buf.format()
```
最经常使用的：
- 注册lsp服务
```lua
vim.lsp.config['lua_ls'] = {
  -- Command and arguments to start the server.
  cmd = { 'lua-language-server' },
  -- Filetypes to automatically attach to.
  filetypes = { 'lua' },
  -- Sets the "workspace" to the directory where any of these files is found.
  -- Files that share a root directory will reuse the LSP server connection.
  -- Nested lists indicate equal priority, see |vim.lsp.Config|.
  root_markers = { { '.luarc.json', '.luarc.jsonc' }, '.git' },
  -- Specific settings to send to the server. The schema is server-defined.
  -- Example: https://raw.githubusercontent.com/LuaLS/vscode-lua/master/setting/schema.json
  settings = {
    Lua = {
      runtime = {
        version = 'LuaJIT',
      }
    }
  }
}
```
- 启动lsp
```lua
vim.lsp.enable('lua_ls')
```

另外可以通过`:checkhealth vim.lsp`来查看lsp服务的运行状态. （在0.11及以前，还可以用`:LspInfo`查看）.

### layer2: nvim-lspconfig
自己从零开始配置各个lsp服务很繁琐，而nvim-lspconfig就是把一些配置好的“预制菜”给端上来.
而且提供了一些command:
```
:LspInfo (alias to :checkhealth vim.lsp) shows the status of active and configured language servers.
:lsp enable [<config_name>] (:LspStart for Nvim 0.11 or older) Start the requested server name. Will only successfully start if the command detects a root directory matching the current config.
:lsp disable [<config_name>] (:LspStop for Nvim 0.11 or older) Stops the given server. Defaults to stopping all servers active on the current buffer. To force stop use :LspStop!
:lsp restart [<client_name>] (:LspRestart for Nvim 0.11 or older) Restarts the given client, and attempts to reattach to all previously attached buffers. Defaults to restarting all active servers.
```

在没有nvim-lspconfig插件时，想要配置一个lsp，就要配置其名称、启动的命令、触发条件、根目录判断规则等:
```lua
vim.lsp.start({
  name = "pyright",
  cmd = { "pyright-langserver", "--stdio" },
  filetypes = { "python" },
  root_dir = vim.fs.root(0, {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Pipfile",
    "pyrightconfig.json",
    ".git",
  }),
})
```
但是有了这个插件后，就变得简单多了：
```lua
require("lspconfig").pyright.setup({})
-- 或者vim.lsp.enable("pyright")
```

想要查看可用的预制lspconfig, 可以运行：`:help lspconfig-all`

### layer3: Mason
前面已经有了nvim-lspconfig来帮我们自动进行lsp的配置，但是安装lsp的过程还需要我们自己来完成。
mason这个插件则是将安装lsp服务（准确来说，还有dap, linter, formatter等）的过程也进行统一管理，是一个针对lsp版的"lazy.nvim".

使用`:Mason`命令，可以查看所有可用的`lsp`,`dap`,`formatter`,`linter`,比如针对ocaml的：
```
      ocaml-lsp ocamllsp (keywords: ocaml)
      ocamlearlybird (keywords: ocaml)
      ocamlformat (keywords: ocaml)
```
提供包管理命令：
```
:Mason
:MasonInstall pyright
:MasonUninstall pyright
:MasonUpdate
```

`mason-tool-installer.nvim`这个包则是在mason的基础上，提供了自动安装的便捷接口：
```lua
ensure_installed = {
  "pyright",
  "ocaml-lsp",
}
require("mason-tool-installer").setup { ensure_installed = ensure_installed }
```

但是，还有一个问题： 仅针对ocaml的lsp来说，我们在`nvim-lspconfig.nvim`显示的预配置名是`ocamllsp`,但是在Mason中显示的名称是`ocaml-lsp`. 也就是说，这两个管理器所管理的“包”名称未必一样. 在maosn中安装的时候，要使用mason的包名，否则可能安装错误.

这时候，新的hero出现了. 如果我们查看`mason-tool-installer.nvim`的README, 可以看到下面的说明：
```
If mason-lspconfig is installed, mason-tool-installer can accept lspconfig package names unless the integration is disabled.

If mason-null-ls is installed, mason-tool-installer can accept null-ls package names unless the integration is disabled.

If mason-nvim-dap is installed, mason-tool-installer can accept nvim-dap package names unless the integration is disabled.
```
`mason-lspconfig`就是为了实现自动桥接这两种包名而出现的. 它不如mason-tool-installer全面，但是却更加的“好用”，它只需要接受`nvim-lspconfig`的相关名称(如`ocamllsp`)即可安装对应的Lsp.
对应的，`mason-null-ls`处理Linter和Formatter, `mason-nvim-dap`处理Dap.


### 技巧：查看日志
`:messages`查看nvim log
