# Builds this checkout with nix-configs' recipe for pkgs.custom.static-penryn
# (its common/pkgs/static-penryn.nix), the one recipe, called with iMacGBC's
# x86-64 package set as AGENTS.md shows. Its passthru gives .libtcc,
# .devPython and .tests.typecheck.
{ lib, custom }:
custom.static-penryn.override { src = lib.cleanSource ./.; }
