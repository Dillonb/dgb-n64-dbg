{
  description = "dgb-n64 debugger";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgs = forAllSystems (system: import nixpkgs { inherit system; });
      shortRev = with self; if sourceInfo?dirtyShortRev then sourceInfo.dirtyShortRev else sourceInfo.shortRev;
    in
    {
      # packages = forAllSystems (system: {
      #   default = pkgs.${system}.stdenv.mkDerivation {
      #     name = "dgb-n64-dbg";
      #     version = shortRev;
      #     dontUnpack = true;
      #     buildInputs = with pkgs.${system}; [
      #       (python312.withPackages (pythonPackages: with pythonPackages; [
      #         textual
      #         capstone
      #         requests
      #       ]))
      #     ];
      #     installPhase = ''
      #       install -Dm755 ${./dbg.py} $out/bin/dgb-n64-dbg
      #       install -Dm755 ${./emulator_connector.py} $out/bin/emulator_connector.py
      #       install -Dm755 ${./dbg.tcss} $out/bin/dbg.tcss
      #     '';
      #   };
      # });

      packages = forAllSystems (system: {
        default = pkgs.${system}.python312Packages.buildPythonPackage {
          pname = "dgb-n64-dbg";
          version = shortRev;
          format = "pyproject";
          src = ./.;
          propagatedBuildInputs = with pkgs.${system}.python312Packages; [ textual capstone requests hatchling ];
        };
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/dgb-n64-dbg";
        };
      });

      devShells = forAllSystems (system: {
        default = pkgs.${system}.mkShell {
          packages = with pkgs.${system}; [
            python312Full
            python312Packages.textual
            python312Packages.capstone
            python312Packages.requests
          ];
        };
      });
    };
}

