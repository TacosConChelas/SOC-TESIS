{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  name = "soc-tesis-ansible";

  # terraform NO va aqui: el pin de nixpkgs trae 1.15.3 y
  # terraform/lab/versions.tf exige >= 1.16.3. Se usa el terraform del host.
  packages = with pkgs; [
    ansible
    ansible-lint
    shellcheck
    openssh
    (python3.withPackages (ps: [ ps.pyyaml ]))
  ];

  shellHook = ''
    echo "soc-tesis ansible shell"
    echo "  ansible:   $(ansible --version | head -1)"
    echo "  terraform: $(command -v terraform || echo 'NO ENCONTRADO (requiere >= 1.16.3)')"
    echo "  uso:       make -C ansible preflight"
    echo "  docker:    se usa el demonio del host (privileged + cgroupns=host)"
  '';
}
