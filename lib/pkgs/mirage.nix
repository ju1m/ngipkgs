{
  stdenv,
  lib,
  opam-nix,
  ...
}:

rec {
  # Description: run `mirage configure` on source,
  # with mirage, dune, and ocaml from `opam-nix`.
  configure =
    {
      pname,
      version,
      mirageDir ? ".",
      query,
      src,
      target,
      opamPackages ? opam-nix.queryToScope { } ({ mirage = "*"; } // query),
      ...
    }:
    stdenv.mkDerivation {
      name = "${pname}-${target}";
      inherit src version;
      buildInputs = with opamPackages; [ mirage ];
      nativeBuildInputs = with opamPackages; [
        dune
        ocaml
      ];
      buildPhase = ''
        runHook preBuild
        mirage configure -f ${mirageDir}/config.ml -t ${target}
        # Description: move Opam file to root so a recursive search for opam files isn't required.
        # Prefix it so it doesn't interfere with other packages.
        cp ${mirageDir}/mirage/${pname}-${target}.opam ${pname}-${target}.opam
        runHook postBuild
      '';
      installPhase = ''
        runHook preBuild
        cp -R . $out
        runHook postBuild
      '';
    };

  # Description: read opam files from mirageConf and build the unikernel.
  build =
    {
      pname,
      version,
      depexts ? [ ],
      mirageDir ? ".",
      queryArgs ? { },
      query ? { },
      monorepoQuery,
      ...
    }@args:
    let
      mirageConf = configure args;
      monorepo = opam-nix.buildOpamMonorepo { } mirageConf monorepoQuery;
      packages = (opam-nix.buildOpamProject queryArgs mirageConf.name mirageConf query).overrideScope (
        finalOpam: previousOpam: {
          ${mirageConf.name} = previousOpam.${mirageConf.name}.overrideAttrs (previousAttrs: {
            inherit version;
            __intentionallyOverridingVersion = true;
            # ToDo: pick depexts of deps in monorepo?
            buildInputs = previousAttrs.buildInputs ++ depexts;
            env =
              previousAttrs.env or { }
              // lib.optionalAttrs (finalOpam ? ocaml-solo5) {
                OCAMLFIND_CONF = "${finalOpam.ocaml-solo5}/lib/findlib.conf";
              };
            buildPhase = ''
              #runHook preBuild
              mkdir duniverse
              echo '(vendored_dirs *)' > duniverse/dune
              ${lib.concatStringsSep "\n" (
                lib.mapAttrsToList (
                  # ToDo: get dune build to pick up symlinks?
                  name: path: "cp -r ${path} duniverse/${lib.toLower name}"
                ) monorepo
              )}
              # Note: doesn't fail on warnings
              dune build ${mirageDir} --profile release
              #runHook postBuild
            '';
            installPhase = ''
              #runHook preInstall
              mkdir $out
              cp -L ${mirageDir}/dist/${pname}* $out/
              #runHook postInstall
            '';
          });
        }
      );
      unikernel = packages.${mirageConf.name};
    in
    unikernel.overrideAttrs (previousAttrs: {
      passthru = previousAttrs.passthru // {
        inherit
          monorepo
          packages
          ;
      };
    });

  possibleTargets = [
    "xen"
    "qubes"
    "unix"
    "macosx"
    "virtio"
    "hvt"
    "spt"
    "muen"
    "genode"
  ];
}
