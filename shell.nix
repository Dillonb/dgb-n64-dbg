{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    python311Full
    python311Packages.textual
    python311Packages.capstone
    python311Packages.requests
  ];
}
