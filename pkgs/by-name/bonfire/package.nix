{ lib, callPackage }:
let
  generic = callPackage ./generic.nix { };
in
lib.recurseIntoAttrs (
  lib.genAttrs
    [
      "community"
      "cooperation"
      "coordination"
      "ember"
      "open_science"
      "social"
    ]
    (
      flavour:
      generic.overrideAttrs (previousAttrs: {
        passthru = lib.recursiveUpdate previousAttrs.passthru {
          env.FLAVOUR = flavour;
        };
      })
    )
)
