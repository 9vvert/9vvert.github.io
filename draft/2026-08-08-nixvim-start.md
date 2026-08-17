---
title: Nixvim - configuring neovim in a "nix" way
categories: [note, nixos]
tags: [note, system]
---

### Review of flake

A 'flake' has `inputs` and `outputs`. We could import other flakes in `inputs`, while export something in `outputs` so that other flakes can also import them. 

```nix
{
  description = "A simple NixOS flake";

  inputs = {
    nixpkgs25_11.url = "github:NixOS/nixpkgs/nixos-25.11";
    # nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs.url = "git+https://mirrors.tuna.tsinghua.edu.cn/git/nixpkgs.git?ref=nixos-26.05&shallow=1";
    
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";
    quickshell = {
      url = "git+https://git.outfoxxed.me/outfoxxed/quickshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    noctalia = {
      url = "github:noctalia-dev/noctalia";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    niri = {
      url = "github:sodiboo/niri-flake";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixvim = {
      url = "path:/home/woc/repo/nixvim-config";
    };
    pyghidra-mcp.url =  "github:9vvert/pyghidra-mcp";
    pwndbg.url = "github:pwndbg/pwndbg";

    qqmusic-mpris-bridge = {
      url = "path:/home/woc/repo/qqmusic-mpris-bridge";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    
    home-manager = {
          url = "github:nix-community/home-manager/release-26.05";
            inputs.nixpkgs.follows = "nixpkgs";
        };
    daeuniverse.url = "github:daeuniverse/flake.nix";
    codex-cli-nix.url = "github:sadjow/codex-cli-nix";
	
  };
  outputs = { 
    self, 
    nixpkgs, 
    home-manager, 
    noctalia, 
    codex-cli-nix,
    nixvim,
    ... 
  }@inputs: let
    systems = [
      "x86_64-linux"

    ];
    forAllSystems = nixpkgs.lib.genAttrs systems; 
  in
    {
    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);

    overlays = import ./overlays {inherit inputs;};
    nixosModules.default = import ./modules/nixos;
    homeManagerModules.default = import ./modules/home-manager;
    nixosConfigurations = {
      "nixos" = nixpkgs.lib.nixosSystem {
        specialArgs = {
          inherit inputs;
          configRoot = self;  
        };
        modules = [
          ./nixos/configuration.nix
        ];
      };
    };
    homeConfigurations = {
      "woc" = home-manager.lib.homeManagerConfiguration {
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
        extraSpecialArgs = {inherit inputs;};
        modules = [
          ./home-manager/home.nix
        ];
      };
    };
  };
}
```

#### Use exported packages

Take `codex-cli-nix` as an example. 

> https://github.com/sadjow/codex-cli-nix

It has suck `flake.nix`:

```nix
{
  description = "Nix flake for OpenAI Codex CLI - AI coding assistant in your terminal";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      overlay = final: prev: {
        codex = final.callPackage ./package.nix { runtime = "native"; };
        codex-node = final.callPackage ./package.nix { runtime = "node"; };
      };
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          overlays = [ overlay ];
        };
      in
      {
        packages = {
          default = pkgs.codex;
          codex = pkgs.codex;
          codex-node = pkgs.codex-node;
        };
        
        apps = {
          default = {
            type = "app";
            program = "${pkgs.codex}/bin/codex";
          };
          codex = {
            type = "app";
            program = "${pkgs.codex}/bin/codex";
          };
          codex-node = {
            type = "app";
            program = "${pkgs.codex-node}/bin/codex-node";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            nixpkgs-fmt
            nix-prefetch-git
            cachix
          ];
        };
      }) // {
        overlays.default = overlay;
      };
}
```

Its `outputs` has `packages.default` -> `pkgs.codex` -> `overlay.codex` -> `package.nix`

Tje `package.nix` actually serves as a nix derivation. (It is a `stdenv.mkDerivation` function)

```nix
{...}:
let ... in
...
stdenv.mkDerivation rec {
  ...
}
```

We can then put that derivation into `home.packages`(for home-manager) or `environment.systemPackages`(for nixos) to install it:

```nix
{pkgs, inputs, ...}:

{
  home.packages = with pkgs; [
    inputs.codex-cli-nix.packages.${pkgs.stdenv.hostPlatform.system}.default
  ];
}
```

#### Use exported 

Except for packages, `dae` provides another way to use it.

> https://github.com/daeuniverse/flake.nix

```nix
{
  description = "Nix flake for dae and daed";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      flake-parts,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { flake-parts-lib, withSystem, ... }:
      {
        partitionedAttrs = {
          checks = "dev";
          devShells = "dev";
        };
        ......
        imports = [
          flake-parts.flakeModules.partitions
          flake-parts.flakeModules.easyOverlay
        ];
        systems = [
          "x86_64-linux"
          "aarch64-linux"
        ];
        perSystem =
          {
            self',
            pkgs,
            system,
            config,
            lib,
            ...
          }:
          ......
        flake =
          let
            moduleName = [
              "dae"
              "daed"
            ];
            genFlake = n: {
              nixosModules.${n} = flake-parts-lib.importApply ./${n}/module.nix {
                inherit withSystem;
              };
            };
          in
          inputs.nixpkgs.lib.mkMerge (map genFlake moduleName);
      }
    );
}
```

It exported two modules `dae` and `daed`.

`./dae/module.nix`:

```nix
{ withSystem }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  ...
in
{
  # disables Nixpkgs dae module to avoid conflicts
  disabledModules = [ "services/networking/dae.nix" ];

  options = {
    services.dae = {
      enable = mkEnableOption "dae, a Linux high-performance transparent proxy solution based on eBPF";

      package = mkPackageOption (withSystem system ({ config, ... }: config.packages)) "dae" {
        pkgsText = "flake.packages.$\{pkgs.system}.dae";
      };

      ...

      openFirewall = mkOption {
        type = types.submodule {
          options = {
            enable = mkEnableOption "opening {option}`port` in the firewall";
            port = mkOption {
              type = types.port;
              description = ''
                Port to be opened. Consist with field `tproxy_port` in config file.
              '';
            };
          };
        };
        default = {
          enable = true;
          port = 12345;
        };
        defaultText = literalExpression ''
          {
            enable = true;
            port = 12345;
          }
        '';
        description = ''
          Open the firewall port.
        '';
      };

      configFile = mkOption {
        type =
          let
            inherit (types) nullOr addCheck str;
            isAbsolutePathString = x: lib.substring 0 1 x == "/";
            isNotInStore = x: !lib.hasPrefix builtins.storeDir x;
            combineTopic = x: isAbsolutePathString x && isNotInStore x;
          in
          (nullOr (addCheck str combineTopic))
          // {
            description = "${types.str.description} (with check: should be absolute path **string** which not a store path)";
          };
        default = null;
        example = ''"/path/to/your/config.dae"'';
        description = ''
          The absolute path string of dae config file which not in nix store,
          end with `.dae`. Will fallback to `"/etc/dae/config.dae"` if this is not set.
        '';
      };

      config = mkOption {
        type = with types; (nullOr str);
        default = null;
        description = ''
          WARNING: This option will expose your config unencrypted world-readable in the nix store.
          Config text for dae.

          See <https://github.com/daeuniverse/dae/blob/main/example.dae>.
        '';
      };

      disableTxChecksumIpGeneric = mkEnableOption "" // {
        description = "See <https://github.com/daeuniverse/dae/issues/43>";
      };
    };
  };

  ...
}
```

It defines some options using `lib.mkOption`. To use it, we need to import it first:
```nix
    imports = [
        inputs.daeuniverse.nixosModules.dae
    ];
```

Then set some attributes.
```nix
  services = {
    dae = {
      enable = true;
      configFile = "/etc/dae/config.dae";
    };
  };

  # Keep dae.service available for manual use, but do not start it at boot.
  systemd.services = {
    dae.wantedBy = lib.mkForce [];
  };
```

###