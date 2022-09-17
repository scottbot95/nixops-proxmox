{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils}:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        packages = rec {
          nixops-proxmox = import ./default.nix { inherit pkgs; };
          default = nixops-proxmox;
        };
      }
    ) // {
      nixosModules = {
        options = import ./nixops_proxmox/nix/proxmox.nix;
      };
    };
}