---
title: Building flake.nix for pyghidra-mcp
categories: [NixOS]
tags: [system, nixos]
---

After configuring basic desktop, terminal and coding environment, Im trying to do binary tools migration. So here comes ghidra.

It is easy to install ghidra in NixOS, just using home-manager. (Also need to set `_JAVA_AWT_WM_NONREPARENTING = 1` to make it working in niri wm).

While im learning how to manage ghidra extension by nix config, I found [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) by chance, which seems to be an excellent tool for AI-workflow. This is my first time trying to biuld a flake.nix for a repo.

### 0x01 Start from template
Forking the reposity and add a template flake.nix:
```nix
{
  description = "pyghidra-mcp packaged with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
    in
    {
      packages.${system}.hello = pkgs.hello;
    };
}
```
Then test by running `nix build .#hello`, which will generated a `result` dir if succeed, with `bin/hello` executable.

### 0x02 Test python package dependencies
Since the repo has `pyproject.toml`, our next step is write some python project building rule according to it.
```toml
name = "pyghidra-mcp"
version = "0.2.2"
description = "Python Command-Line Ghidra MCP"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "click>=8.2.1",
    "click-option-group>=0.5.9",
    "mcp[cli]>=1.26.0",
    "pyghidra>=2.2.1",
    "chromadb>=1.3.5",
    "ghidrecomp>=0.5.8",
]
...
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
...
```

We need to add python version and the most important attribute `buildPythonApplication`(including building backend - `hatchling`, and some dependencies). 

```nix
{
  description = "pyghidra-mcp packaged with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
      # add python
      python = pkgs.python313;
      py = python.pkgs;
    in
    {
      packages.${system}.default = py.buildPythonApplication {
        pname = "pyghidra-mcp";
        version = "0.2.2";

        src = ./.;

        pyproject = true;

        build-system = with py; [
          hatchling
        ];

        # python package dependencies
        dependencies = with py; [
          click
          click-option-group
          mcp 
          pyghidra
          chromadb
          # ghidrecomp
        ];
      };
    };
}
```
However, we cannot garatuee all python package denepdencies are in nixpkgs. So we should test them:
```
pyghidra-mcp on  main [!?] is 📦 v0.2.2 via 🐍 v3.13.12
❯ nix eval github:nixos/nixpkgs/nixos-unstable#python313Packages.click
«derivation /nix/store/f4qvwmhh1zj66qrk6k3x5bj7gqdfh0yr-python3.13-click-8.3.1.drv»
```

> **Choose the correct nix pkgs source**
> First I run:
> 
> ```
> pyghidra-mcp on  main [!?] is 📦 v0.2.2 via 🐍 v3.13.12
> ❯ nix eval nixpkgs#python313Packages.pyghidra
> error: flake 'flake:nixpkgs' does not provide attribute 'packages.x86_64-linux.python313Packages.pyghidra', 'legacyPackages.x86_64-linux.python313Packages.pyghidra' or 'python313Packages.pyghidra' Did you mean pyhidra?
> ```
> This is because `nixpkgs` refers to the value in my system, which is `nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";`.
> However, [pyghidra](https://mynixos.com/nixpkgs/package/python313Packages.pyghidra) is only added in `github:nixos/nixpkgs/nixos-unstable`, not in `nixos-25.11`.
> 
> So I should use:
> 
> ```
> nixos-config on  main [!]
> ❯ nix eval github:nixos/nixpkgs/nixos-unstable#python313Packages.pyghidra
> «derivation /nix/store/yk2f34pcnbr14d9bfbpn16i9y4lfw4hx-python3.13-pyghidra-3.1.0.drv»
> ```
> Perfect! 
> And we notice that the pyghidra package is only included in `python313Packages` and `python314Packages`, not in 3.12 or older version. 
> 
> Btw, if pyghidra is not included in nixpkgs, we can build it by defining
> 
> ```nix
> pyghidra = py.buildPythonPackage rec {
>   pname = "pyghidra";
>   version = "2.2.1";
> 
>   src = py.fetchPypi {
>     inherit pname version;
>     hash = "sha256-0ajGRHpt8QFqOCZmKnXrFPKtcFjJqPSwkyLHOnpPytQ=";   # We can fill the hash with a random value first. When we build it with `nix build -L`, there should be hash not match error, and tell us the right hash.
>   };
> 
>   pyproject = true;
> 
>   build-system = with py; [
>     setuptools
>     wheel
>   ];
> 
>   dependencies = with py; [
>     jpype1
>   ];
> 
>   pythonImportsCheck = [
>     "pyghidra"
>   ];
> };
> ```
{: prompt-warning }

However, `ghidrecomp` is a custom python package written by the author, not included in nixpkgs. Here we need to build it in our flake.nix:
```nix
{
  description = "pyghidra-mcp packaged with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    pyghidra-mcp-src = {
      url = "github:clearbluejar/pyghidra-mcp";
      flake = false;
    };
  };
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
      python = pkgs.python313;
      py = python.pkgs;


      ghidrecomp = py.buildPythonPackage rec {
        pname = "ghidrecomp";
        version = "0.5.9";
        pyproject = true;

        src = pkgs.fetchPypi {
          inherit pname version;
          hash = "sha256-ocluLUidyqMRkO7kXWum8l3VZ/paro/1tQ9JgOood6I=";
        };

        build-system = with py; [
          setuptools
          wheel
        ];

        dependencies = with py; [
          pyghidra
          jpype1
          click
          lxml
          networkx
          pydot
          pyyaml
          requests
        ];
        doCheck = true;

        pythonImportsCheck = [
          "ghidrecomp"
        ];
      };
    in
    {
      ...
    };
}
```

The last thing: in pyproject.toml, it has `mcp[cli]`, which means mcp + extra dependencies using by its cli. So the ultimate dependencies settings are:
```nix
dependencies = with py; [
  click
  click-option-group
  mcp 
  pyghidra
  chromadb
  ghidrecomp
]++ py.mcp.optional-dependencies.cli;
```

### 0x03 Add pyghidra-mcp-cli
We have successfully built `pyghidra-mcp`. It is easy to add a sencond output. 
```nix
{
  description = "pyghidra-mcp packaged with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
      python = pkgs.python313;
      py = python.pkgs;

      ghidrecomp = py.buildPythonPackage rec {
        pname = "ghidrecomp";
        version = "0.5.9";
        pyproject = true;

        src = pkgs.fetchPypi {
          inherit pname version;
          hash = "sha256-ocluLUic2qMREO7kXWum8l3VZ/parj/WtQ9JgOood6I=";
        };

        build-system = with py; [
          setuptools
          wheel
        ];

        dependencies = with py; [
          pyghidra
          jpype1
          click
          lxml
          networkx
          pydot
          pyyaml
          requests
        ];
        doCheck = true;
        pythonImportsCheck = [
          "ghidrecomp"
        ];
      };

      pyghidra-mcp = py.buildPythonApplication {
        pname = "pyghidra-mcp";
        version = "0.2.2";

        src = ./.;

        pyproject = true;

        build-system = with py; [
          hatchling
        ];

        # python package dependencies
        dependencies = with py; [
          click
          click-option-group
          mcp 
          pyghidra    # needs ghidra >= 12.0
          chromadb
          ghidrecomp
        ]++ py.mcp.optional-dependencies.cli;
      };

      pyghidra-mcp-cli = py.buildPythonApplication {
        pname = "pyghidra-mcp-cli";
        version = "0.2.2";

        src = ./cli;
        pyproject = true;

        build-system = with py; [
          hatchling
        ];

        dependencies = with py; [
          click
          aiohttp
          pyghidra-mcp
        ];
      };
    in
    {
      # add both binary
      packages.${system} = {
        default = pkgs.symlinkJoin {
          name = "pyghidra-mcp-with-cli";

          paths = [
              pyghidra-mcp
              pyghidra-mcp-cli
            ];
        };
        pyghidra-mcp = pyghidra-mcp;
        pyghidra-mcp-cli = pyghidra-mcp-cli;
      };
    };
}
```

### 0x04 Add multi-system
```nix
{
  description = "pyghidra-mcp packaged with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;

      pkgsFor = system: import nixpkgs {
        inherit system;
      };
    in
    {
      
      packages = forAllSystems (system:
      let
        pkgs = pkgsFor system;
        python = pkgs.python313;
        py = python.pkgs;

        # build ghidrecomp
        ghidrecomp = py.buildPythonPackage rec {
          pname = "ghidrecomp";
          version = "0.5.9";
          pyproject = true;

          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-ocluLUic2qMREO7kXWum8l3VZ/parj/WtQ9JgOood6I=";
          };

          build-system = with py; [
            setuptools
            wheel
          ];

          dependencies = with py; [
            pyghidra
            jpype1
            click
            lxml
            networkx
            pydot
            pyyaml
            requests
          ];
          doCheck = true;
          pythonImportsCheck = [
            "ghidrecomp"
          ];
        };

        # pyghidra-mcp
        pyghidra-mcp = py.buildPythonApplication {
          pname = "pyghidra-mcp";
          version = "0.2.2";

          src = ./.;

          pyproject = true;

          build-system = with py; [
            hatchling
          ];

          # python package dependencies
          dependencies = with py; [
            click
            click-option-group
            mcp 
            pyghidra    # needs ghidra >= 12.0
            chromadb
            ghidrecomp
          ]++ py.mcp.optional-dependencies.cli;
        };

        # pyghidra-mcp-cli
        pyghidra-mcp-cli = py.buildPythonApplication {
          pname = "pyghidra-mcp-cli";
          version = "0.2.2";

          src = ./cli;
          pyproject = true;

          build-system = with py; [
            hatchling
          ];

          dependencies = with py; [
            click
            aiohttp
            pyghidra-mcp
          ];
        };
      in
      {
        default = pkgs.symlinkJoin {
          name = "pyghidra-mcp-with-cli";
          paths = [
            pyghidra-mcp
            pyghidra-mcp-cli
          ];
        };

        inherit pyghidra-mcp pyghidra-mcp-cli;
      });
      # for nix run
      apps = forAllSystems (system:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/pyghidra-mcp";
          };

          pyghidra-mcp = {
            type = "app";
            program = "${self.packages.${system}.pyghidra-mcp}/bin/pyghidra-mcp";
          };

          pyghidra-mcp-cli = {
            type = "app";
            program = "${self.packages.${system}.pyghidra-mcp-cli}/bin/pyghidra-mcp-cli";
          };
        });
    };
}
```
