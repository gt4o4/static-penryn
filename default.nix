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
  runCommand,
  go,
  glib,
  qemu,
  perf,
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
  # The package directory holds exactly what the tool runs; local bytecode
  # caches stay out of the store path.
  source = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.difference ./static_penryn (
      lib.fileset.maybeMissing ./static_penryn/__pycache__
    );
  };
  goMetadata = runCommand "penryn-go-metadata" { nativeBuildInputs = [ go ]; } ''
    mkdir -p "$out/bin"
    export GOCACHE="$TMPDIR/go-cache"
    CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -ldflags="-s -w" \
      -o "$out/bin/penryn-go-metadata" ${./static_penryn/go_metadata.go}
  '';
in
writeShellApplication {
  name = "static-penryn";
  runtimeInputs = [
    python
    stdenv.cc
    binutils
    qemu
    perf
  ];
  text = ''
    export PENRYN_GOMETA=${goMetadata}/bin/penryn-go-metadata
    export PENRYN_GLIB_CFLAGS="-I${glib.dev}/include/glib-2.0 -I${glib.out}/lib/glib-2.0/include"
    export PYTHONPATH=${source}
    if [[ "''${1-}" == profile ]]; then
      shift
      exec python3 -m static_penryn.profile "$@"
    elif [[ "''${1-}" == workloads ]]; then
      shift
      exec python3 -m static_penryn.workloads "$@"
    elif [[ "''${1-}" == bench ]]; then
      shift
      exec python3 -m static_penryn.bench_apps "$@"
    fi
    exec python3 -m static_penryn.patch --core ${custom.sse42-emu.src}/core "$@"
  '';
}
