{
  bonfire,
  coreutils,
  lib,
  nix,
  nurl,
  writeShellApplication,
  writeTextDir,
  callPackage,
}:
let
  FLAVOUR = bonfire.passthru.env.FLAVOUR;
in
# Documentation: manuals/Contributor/How_to/update/pkgs/bonfire.md
{
  script = writeShellApplication {
    name = "bonfire-update";
    runtimeInputs = [
      bonfire.passthru.yarn-berry.yarn-berry-fetcher
      coreutils
      nix
      nurl
    ];
    text = lib.concatStringsSep "\n" [
      "set -x"

      # ToDo(maint/update): use gitUpdater instead of nurl
      # whenever all extensions have a release tag.
      #
      # Explanation: updating the extensions
      # must come before updating the dependencies in `deps.nix`,
      # which uses the extensions.
      (lib.concatMapStringsSep "\n" (flavour: ''
        mkdir -p pkgs/by-name/bonfire/extensions/${flavour}
        {
          echo "{fetchFromGitHub, ...}:"
          nurl https://github.com/bonfire-networks/${flavour}
        } >pkgs/by-name/bonfire/extensions/${flavour}/fetchFromGitHub.nix
      '') (lib.map (ext: ext.repo) bonfire.passthru.flavour-extensions))

      # Description: update pkgs/by-name/bonfire/${FLAVOUR}/deps.nix
      ''
        deps=$(nix -L --show-trace --extra-experimental-features "nix-command" \
                   build \
                   --option sandbox relaxed \
                   --no-link --print-out-paths \
                   --repair \
                   -f . \
                   bonfire.${FLAVOUR}.passthru.update.package )
        cp -f "$deps" pkgs/by-name/bonfire/extensions/${FLAVOUR}/deps.nix
      ''

      # Description: update pkgs/by-name/bonfire/deps/${name}/yarnOfflineCache.hash
      (lib.concatMapStringsSep "\n" (dep: ''
        mkdir -p pkgs/by-name/bonfire/deps/${dep}/${FLAVOUR}/
        nurl --expr 'let NGIpkgs = import ./. {}; in
          NGIpkgs.bonfire.${FLAVOUR}.yarnOfflineCaches.${dep}
        ' --hash >pkgs/by-name/bonfire/deps/${dep}/${FLAVOUR}/yarnOfflineCache.hash
      '') (lib.attrNames bonfire.yarnOfflineCaches))

      # Description: update pkgs/by-name/bonfire/deps/${name}/{missingHashes.json,yarnOfflineCache.hash}
      (lib.concatMapStringsSep "\n" (dep: ''
        nix -L --extra-experimental-features "nix-command" build --no-link -f . \
          bonfire.${FLAVOUR}.yarnOfflineCaches.${dep}.src
        yarnLock=$(nix -L --extra-experimental-features "nix-command" eval --raw -f . \
          bonfire.${FLAVOUR}.yarnOfflineCaches.${dep}.passthru.yarnLock)
        yarn-berry-fetcher missing-hashes "$yarnLock" \
          >pkgs/by-name/bonfire/deps/${dep}/${FLAVOUR}/missingHashes.json
        nurl --expr 'let NGIpkgs = import ./. {}; in
          NGIpkgs.bonfire.${FLAVOUR}.yarnOfflineCaches.${dep}
        ' --hash >pkgs/by-name/bonfire/deps/${dep}/${FLAVOUR}/yarnOfflineCache.hash
      '') (lib.attrNames bonfire.yarnBerryOfflineCaches))

      # Description: update pkgs/by-name/bonfire/deps/ex_cldr/hash
      # Explanation: fetchFromGitHub is used instead of fetchHex
      # to let nix instead of mix provision locales.
      ''
        mkdir -p pkgs/by-name/bonfire/deps/ex_cldr/${FLAVOUR}/
        nurl --expr 'let NGIpkgs = import ./. {}; in
          NGIpkgs.bonfire.${FLAVOUR}.passthru.mixNixDeps.ex_cldr.src.overrideAttrs (previousAttrs: { nativeBuildInputs = previousAttrs.nativeBuildInputs or [] ++ [ NGIpkgs.pkgs.cacert ]; })
        ' --hash >pkgs/by-name/bonfire/deps/ex_cldr/${FLAVOUR}/fetchFromGitHub.hash
      ''
    ];
  };

  package = callPackage ../../../profiles/pkgs/development/beam-modules/mix-update.nix {
    package = bonfire.overrideAttrs (previousAttrs: {
      preBuild = "";
      postPatch =
        previousAttrs.postPatch or ""
        + lib.concatStringsSep "\n" [
          # Explanation: re-enable downloading of locales.
          ''
            cat >>config/config.exs <<EOF
            config :bonfire_common, Bonfire.Common.Localise.Cldr,
              force_locale_download: false
            EOF
          ''
        ];
    });
    # Explanation: deps_nix needs to be injected into bonfire's mix.exs
    deps_nix_injection_pattern = "extra_deps =";
  };
}
