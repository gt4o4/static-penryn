# Experimental tool only; does not replace any installed application.
# Call with iMacGBC's package set so custom.sse42-emu.src is the fleet pin.
{
  lib,
  writeShellApplication,
  python3,
  stdenv,
  binutils,
  custom,
  fetchurl,
  autoPatchelfHook,
}:
let
  # This nixpkgs revision has no Python iced-x86 package. Its CPython abi3
  # wheel works with the package set's Python; used only while patching.
  iced = python3.pkgs.buildPythonPackage {
    pname = "iced-x86";
    version = "1.21.0";
    format = "wheel";
    src = fetchurl {
      url = "https://files.pythonhosted.org/packages/5d/08/054cac5c4f435a243e423323783992c78c7c2f22cf2269fcca145b8423af/iced_x86-1.21.0-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
      hash = "sha256-SJeJN3v8H+QyvSqKV4DJ8+fDW+LmEzsN5UMs2QHK0yw=";
    };
    nativeBuildInputs = [ autoPatchelfHook ];
    buildInputs = [ stdenv.cc.cc.lib ];
    pythonImportsCheck = [ "iced_x86" ];
    meta.platforms = [ "x86_64-linux" ];
  };
  python = python3.withPackages (p: [
    iced
    p.pyelftools
  ]);
  source = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./patch.py
      ./dataflow.py
      ./elfcheck.py
      ./lower.py
      ./strings.py
      ./strings.c
    ];
  };
in
writeShellApplication {
  name = "static-penryn";
  runtimeInputs = [
    python
    stdenv.cc
    binutils
  ];
  text = ''
    exec python3 ${source}/patch.py --core ${custom.sse42-emu.src}/core "$@"
  '';
}
