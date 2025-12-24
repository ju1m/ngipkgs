{
  _experimental-update-script-combinators,
  beam,
  bonfire,
  callPackage,
  cargo,
  fetchFromGitHub,
  fetchYarnDeps,
  gitUpdater,
  lexbor,
  lib,
  nodejs,
  pkgs,
  rustc,
  yarn,
  yarn-berry_4,
  yarnConfigHook,
  ...
}:
let
  beamPkgs = beam.packages.erlang_28.extend (
    final: previous: {
      buildMix = final.callPackage ../../../profiles/pkgs/development/beam-modules/build-mix.nix { };
      mixRelease = final.callPackage ../../../profiles/pkgs/development/beam-modules/mix-release.nix { };
    }
  );
in
beamPkgs.mixRelease (finalAttrs: {
  pname = "bonfire";
  # Explanation: unstable version which includes fixes from:
  # https://github.com/bonfire-networks/bonfire-app/issues/1637
  version = "1.0.1-alpha.41";
  src = fetchFromGitHub {
    owner = "bonfire-networks";
    repo = "bonfire-app";
    tag = "v${finalAttrs.version}";
    hash = "sha256-OItvyI0aF7n/lGk5t2TsaOonHrqdplAcC2eOzeHigzY=";
  };
  inherit (finalAttrs.passthru.beamPackages) erlang elixir;
  #inherit (finalAttrs.passthru) env mixNixDeps;
  passthru = {
    env = {
      FLAVOUR = "ember";

      WITH_IMAGE_VIX = "true";
      WITH_GIT_DEPS = "1";
      WITH_FORKS = "0";
      WITH_DOCKER = "no";

      # Explanation: from justfile's _ext-migrations-copy
      MIX_OS_DEPS_COMPILE_PARTITION_COUNT = "1";

      # Remark: somehow lib/api/graphql_masto_adapter.ex
      # has become extremely slow to compile.
      # Issue: https://github.com/bonfire-networks/bonfire-app/issues/916#issuecomment-3656556058
      WITH_API_GRAPHQL = "1";

      # ToDo(functional/completeness): support this?
      #WITH_XMPP = "1";
    };

    deps = ./. + "/extensions/${finalAttrs.passthru.env.FLAVOUR}/deps.nix";
    mixNixDeps = import finalAttrs.passthru.deps {
      inherit lib pkgs;
      inherit (finalAttrs.passthru) beamPackages;
      overrideFenixOverlay = finalPkgs: previousPkgs: {
        # Explanation: deps_nix generates ${finalAttrs.passthru.env.FLAVOUR}/deps.nix
        # assuming fenix is used to provide rustToolchain,
        # but so far the rustc and cargo from nixpkgs are enough,
        # and more likely already in one's Nix store.
        fenix = {
          stable = {
            inherit rustc cargo;
          };
        };
      };
      overrides =
        finalMixPkgs: previousMixPkgs:
        {
          bonfire_common = previousMixPkgs.bonfire_common.overrideAttrs (previousAttrs: {
            # Explanation: remove a dangling symlink pointing out of bonfire_common…
            postPatch = previousAttrs.postPatch or "" + ''
              rm priv/localisation
            '';
          });
          bonfire_data_access_control =
            (previousMixPkgs.bonfire_data_access_control.override (previousArgs: {
              beamDeps =
                previousArgs.beamDeps
                ++ (with finalMixPkgs; [
                  # Explanation: missing dependency in upstream deps.hex…
                  typed_ecto_schema
                ]);
            })).overrideAttrs
              (previousAttrs: {
                postPatch = previousAttrs.postPatch or "" + ''
                  cat >>deps.hex <<EOF

                  typed_ecto_schema = ">= 0.0.0"
                  EOF
                '';
              });
          bonfire_data_activity_pub =
            previousMixPkgs.bonfire_data_activity_pub.overrideAttrs
              (previousAttrs: {
                # Explanation: missing transitive dependency in upstream's deps.hex…
                postPatch = previousAttrs.postPatch or "" + ''
                  cat >>deps.hex <<EOF

                  typed_ecto_schema = ">= 0.0.0"
                  EOF
                '';
              });
          bonfire_data_edges = previousMixPkgs.bonfire_data_edges.overrideAttrs (previousAttrs: {
            # Explanation: missing transitive dependency in upstream's deps.hex…
            postPatch = previousAttrs.postPatch or "" + ''
              cat >>deps.hex <<EOF

              typed_ecto_schema = ">= 0.0.0"
              EOF
            '';
          });
          bonfire_federate_activitypub =
            previousMixPkgs.bonfire_federate_activitypub.overrideAttrs
              (previousAttrs: {
                # Explanation: missing dependency in upstream's deps.git…
                postPatch = previousAttrs.postPatch or "" + ''
                  cat >>deps.git <<EOF

                  bonfire_ui_common = "https://github.com/bonfire-networks/bonfire_ui_common"
                  EOF
                '';
              });
          bonfire_ui_common = previousMixPkgs.bonfire_ui_common.overrideAttrs (
            finalAttrs: previousAttrs: {
              postPatch =
                previousAttrs.postPatch or ""
                + lib.concatStringsSep "\n" [
                  # Explanation: remove a dangling symlink pointing out of the repo…
                  ''
                    rm priv/static
                  ''
                ];
            }
          );
          bonfire_ui_me = previousMixPkgs.bonfire_ui_me.overrideAttrs (previousAttrs: {
            # Explanation: missing dependency in upstream's deps.hex…
            postPatch = previousAttrs.postPatch or "" + ''
              cat >>deps.hex <<EOF

              absinthe_phoenix = ">= 0.0.0"
              EOF
            '';
          });
          ex_cldr = previousMixPkgs.ex_cldr.overrideAttrs (previousAttrs: rec {
            # Explanation: use the GitHub sources instead of Hex,
            # as it otherwise tries to download the locales when building reverse-dependencies.
            src = fetchFromGitHub {
              owner = "elixir-cldr";
              repo = "cldr";
              rev = "v${previousAttrs.version}";
              hash = lib.readFile (./. + "/deps/ex_cldr/${finalAttrs.passthru.env.FLAVOUR}/fetchFromGitHub.hash");
            };
            postInstall = previousAttrs.postInstall or "" + ''
              cp $src/priv/cldr/locales/* $out/lib/erlang/lib/ex_cldr-${previousAttrs.version}/priv/cldr/locales/
            '';
          });
          iconify_ex = previousMixPkgs.iconify_ex.overrideAttrs (
            finalAttrs: previousAttrs: {
              # Explanation: make iconify.ex look for its assets
              # in $out/assets/… instead of /build/source/assets/….
              postPatch = previousAttrs.postPatch or "" + ''
                substituteInPlace lib/iconify.ex \
                  --replace-fail 'File.cwd!()' "\"$out\""
              '';
            }
          );
          # Relevant: https://github.com/code-supply/deps_nix/pull/33
          lazy_html = previousMixPkgs.lazy_html.overrideAttrs (previousAttrs: {
            # Explanation: somehow `mix compile --no-deps-check`
            # replaces Fine.include_dir() by "/build/fine-0.1.4/c_include"
            # a path which is not available when building lazy_html there.
            #
            # Explanation: lazy_html being built in a sandbox
            # it cannot download its precompiled binary,
            # it then attempt to compile from source by first git cloning lexbor,
            # but lexbor is already packaged in nixpkgs,
            # and to let the Makefile reuse it, it's enough to empty @lexbor_git_sha.
            postPatch = ''
              substituteInPlace mix.exs \
                --replace-fail "Fine.include_dir()" '"${finalMixPkgs.fine}/src/c_include"' \
                --replace-fail '@lexbor_git_sha "244b84956a6dc7eec293781d051354f351274c46"' '@lexbor_git_sha ""'
            '';

            # Explanation: workaround:
            # (File.Error) could not make directory (with -p) "/homeless-shelter/.cache/elixir_make":
            # no such file or directory
            preConfigure = previousAttrs.preConfigure or "" + ''
              export ELIXIR_MAKE_CACHE_DIR="$TMPDIR/.cache"
            '';

            # Explanation: nix provides lexbor.
            preBuild = previousAttrs.preBuild or "" + ''
              export LEXBOR_GIT_SHA=
              install -Dm644 \
                -t _build/c/third_party/lexbor/$LEXBOR_GIT_SHA/build \
                ${lexbor}/lib/liblexbor_static.a
            '';
            buildInputs = previousAttrs.buildInputs or [ ] ++ [
              lexbor
            ];
          });
        }
        // lib.optionalAttrs (previousMixPkgs ? "evision") {
          evision = (callPackage deps/evision.nix { } finalMixPkgs previousMixPkgs).evision;
        };
    };

    flavour-extensions = (
      let
        urlAsKey = lib.map (ext: ext // { key = ext.url; });
      in
      builtins.genericClosure {
        startSet = urlAsKey [ finalAttrs.passthru.extensions.${finalAttrs.passthru.env.FLAVOUR} ];
        operator = ext: urlAsKey ext.passthru.extensions;
      }
    );
    extensions = {
      community = callPackage extensions/community/fetchFromGitHub.nix { } // {
        passthru = {
          extensions = with finalAttrs.passthru.extensions; [
            social
          ];
        };
      };
      cooperation = callPackage extensions/cooperation/fetchFromGitHub.nix { } // {
        passthru = {
          extensions = with finalAttrs.passthru.extensions; [
            ember
          ];
        };
      };
      coordination = {
        community = callPackage extensions/coordination/fetchFromGitHub.nix { } // {
          passthru = {
            extensions = with finalAttrs.passthru.extensions; [
              community
            ];
          };
        };
      };
      ember = callPackage extensions/ember/fetchFromGitHub.nix { } // {
        passthru = {
          extensions = [ ];
        };
        /*
          ember = previousMixPkgs.ember.overrideAttrs (previousAttrs: {
            # Explanation: ember list rustler_precompiled as a dependency in deps.hex,
            # letting deps_nix believe it needs it,
            # and thus expecting a native/ directory with a Rust crate.
            # This is not the case, so remove it.
            preConfigure = "";
          });
        */
      };
      open_science = callPackage extensions/open_science/fetchFromGitHub.nix { } // {
        passthru = {
          extensions = with finalAttrs.passthru.extensions; [
            social
          ];
        };
      };
      social = callPackage extensions/social/fetchFromGitHub.nix { } // {
        passthru = {
          extensions = with finalAttrs.passthru.extensions; [
            ember
          ];
        };
        /*
          social = previousMixPkgs.social.overrideAttrs (previousAttrs: {
            # Explanation: social list rustler_precompiled as a dependency in deps.hex,
            # letting deps_nix believe it needs it,
            # and thus expecting a native/ directory with a Rust crate.
            # This is not the case, so remove the problematic part.
            preConfigure = "";
          });
        */
      };
    };

    yarnOfflineCaches =
      lib.genAttrs
        (lib.filter (pname: finalAttrs.passthru.mixNixDeps ? pname) [
          "bonfire_editor_milkdown"
          "bonfire_geolocate"
          "iconify_ex"
        ])
        (
          pname:
          fetchYarnDeps {
            name = "${pname}-yarn-deps";
            yarnLock = "${finalAttrs.passthru.mixNixDeps.${pname}.src}/assets/yarn.lock";
            hash = lib.readFile (
              ./. + "/deps/${pname}/${finalAttrs.passthru.env.FLAVOUR}/yarnOfflineCache.hash"
            );
          }
        );
    yarn-berry = yarn-berry_4;
    yarnBerryOfflineCaches =
      lib.genAttrs
        (lib.filter (pname: finalAttrs.passthru.mixNixDeps ? pname) [
          "bonfire_ui_common"
        ])
        (
          pname:
          finalAttrs.passthru.yarn-berry.fetchYarnBerryDeps {
            name = "${pname}-yarn-deps";
            yarnLock = "${finalAttrs.passthru.mixNixDeps.${pname}.src}/assets/yarn.lock";
            hash = lib.readFile (
              ./. + "/deps/${pname}/${finalAttrs.passthru.env.FLAVOUR}/yarnOfflineCache.hash"
            );
            missingHashes = ./. + "/deps/${pname}/${finalAttrs.passthru.env.FLAVOUR}/missingHashes.json";
          }
        );

    # Warning(maint/update): bonfire having a huge dependency closure,
    # expect a lot of downloads during several minutes.
    update = callPackage ./update.nix { bonfire = bonfire.${finalAttrs.passthru.env.FLAVOUR}; };
    updateScript = _experimental-update-script-combinators.sequence [
      (gitUpdater {
        rev-prefix = "v";
      })
      {
        command = [ (lib.getExe finalAttrs.update.script) ];
        # Explanation: required by _experimental-update-script-combinators.sequence:
        # > error: Combining update scripts with features enabled
        # > (other than “silent” scripts and an optional single script with “commit”)
        # > is currently unsupported.
        supportedFeatures = [ "silent" ];
      }
    ];

    # Explanation: to build its Erlang config (config/)
    # and some JavaScript imports (**/deps.hooks.js)
    # bonfire-app overlays symlinks from bonfire-app, ember and ${finalAttrs.passthru.env.FLAVOUR}.
    bonfire-setup =
      pkgs.runCommandLocal "bonfire-setup"
        {
          inherit (finalAttrs) src;
          nativeBuildInputs = [
            pkgs.just
          ];
        }
        (
          lib.concatStringsSep "\n" [
            ''
              set -eu -o pipefail
              mkdir $out
              cd $out
            ''

            # Explanation: reuse justfile's convoluted rules to merge configs.
            # Note that:
            # - libraries (eg. surface_from_helpers) want to replace files inside config/
            # - there are relative paths **inside** files (eg. ../../deps/… paths in **/deps.hook.js),
            # preventing the use of symlinks for them
            # because their path is canonicalized before including them,
            # so that cannot be a symlink pointing out of this setup…
            #
            # Note that `just _assets-ln` is not called,
            # since bonfire_ui_common has not been built yet,
            # assets/ will be set later when building the bonfire package with mixRelease.
            ''
              mkdir extensions
            ''
            (lib.concatMapStringsSep "\n" (ext: ''
              cp --no-preserve=mode -r ${ext} extensions/${ext.repo}
            '') finalAttrs.passthru.flavour-extensions)

            ''
              cp --no-preserve=mode -r ${finalAttrs.src}/config .
              cp --no-preserve=mode -rs ${finalAttrs.src}/justfile .
              just flavour_make_symlinks ${finalAttrs.passthru.env.FLAVOUR}
            ''

            # Explanation: some flavour do not have assets (eg. open_science)
            # causing flavour_make_symlinks to create a dangling symlink
            # that makes the build fail.
            ''
              test -e config/current_flavour/assets ||
              rm config/current_flavour/assets
            ''

            # Explanation: from: just _flavour_install
            ''
              $SHELL extensions/${finalAttrs.passthru.env.FLAVOUR}/install.sh --yes
            ''

            # Explanation: unsymlink config/config.exs to modify it
            ''
              cp --no-preserve=mode --remove-destination --force "$(realpath config/config.exs)" config/config.exs
            ''

            # Explanation: set skip_compilation? to let nix provide Rust libraries,
            # and load_from because rustler defaults to priv/native/#{crate}
            # but deps_nix installs into priv/native/lib#{crate}.
            #
            # Issue: https://github.com/code-supply/deps_nix/issues/36
            ''
              cat >>config/config.exs <<EOF

              config :autumn,
                     Autumn.Native,
                     skip_compilation?: true,
                     load_from: {:autumn, "priv/native/libautumnus_nif"}
              config :mdex,
                     MDEx.Native,
                     skip_compilation?: true,
                     load_from: {:mdex, "priv/native/libcomrak_nif"}
              config :mjml,
                     Mjml.Native,
                     skip_compilation?: true,
                     load_from: {:mjml, "priv/native/libmjml_nif"}
              EOF
            ''
          ]
        );

    beamPackages = beamPkgs // {
      buildMix =
        previousArgs:
        lib.makeOverridable beamPkgs.buildMix (
          #finalAttrs:
          previousArgs
          // {
            # Explanation: in some of its own dependencies,
            # bonfire uses Mess for managing dependencies,
            # which requires to vendor-in mess.exs,
            # but as of Bonfire 1.0.0 some are outdated wrt. bonfire-app/lib/mix/mess.exs
            # causing mix to fail hard… so, override globally without remorse.
            postPatch = previousArgs.postPatch or "" + ''
              if grep -qF Mess mix.exs; then
                ln -fns \${finalAttrs.src + "/lib/mix/mess.exs"} mess.exs
                # Explanation: some mix.exs depend on mess.exs but do not load it…
                sed -i mix.exs -e 's/^ *# *Code.eval_file(\"mess.exs\"/Code.eval_file(\"mess.exs\"/'
              fi
            '';

            # Explanation: get a writable extensions.
            # Because some dependencies generate files into them,
            # eg. surface_form_helpers generates into config/current_flavour/assets/hooks/
            # which points to extensions/social/assets/hooks/
            appConfigPath = "${finalAttrs.passthru.bonfire-setup}/config";
            env = previousArgs.env or { } // {
              inherit (finalAttrs.passthru.env) FLAVOUR;
              # Explanation: config/bonfire_common.exs
              # uses this to set :rustler_precompiled, force_build_all
              # which is needed to let nix provision Rust libraries.
              RUSTLER_BUILD_ALL = "true";
            };
            inherit (finalAttrs) mixEnv;
            postConfigure = previousArgs.postConfigure or "" + ''
              cp --no-preserve=mode -r ${finalAttrs.passthru.bonfire-setup}/extensions .
            '';
          }
        );
    };
  };
  mixEnv = "prod";
  # Explanation: useless in Nix and incompatible with Surface.
  erlangDeterministicBuilds = false;

  # ToDo(optimize/size): test if it works.
  #stripDebug = true;

  nativeBuildInputs = [
    finalAttrs.passthru.yarn-berry.yarnBerryConfigHook
    yarnConfigHook
    nodejs
  ];

  # Explanation: to run yarnConfigHook multiple times manually.
  dontYarnInstallDeps = true;
  dontYarnBerryInstallDeps = true;

  postConfigure = lib.concatStringsSep "\n" [
    # Explanation: bonfire_ui_common & co. look like Elixir libraries,
    # but can only be built correctly inside bonfire-app.
    ''
      cp --no-preserve=mode -r ${finalAttrs.passthru.bonfire-setup}/* .
      mkdir -p extensions
      ln -s ../deps/bonfire_ui_common \
            extensions/bonfire_ui_common
      ln -s extensions/bonfire_ui_common/assets \
            assets
    ''

    # FixMe(functional/completeness): workaround
    # some settings have a different value during runtime compared to compile time,
    # at least :rustler_precompiled and :mime
    # Issue: https://github.com/bonfire-networks/bonfire-app/issues/1696
    ''
      cat >>config/runtime.exs <<EOF
        config :rustler_precompiled, force_build_all: true
      EOF
      substituteInPlace mix.exs \
        --replace-fail "runtime_config_path:" "validate_compile_env: false, runtime_config_path:"
    ''

    # Explanation: make runtime.exs configurable at runtime
    # (eg. in a NixOS module) without rebuilding the package.
    ''
      cat >>config/runtime.exs <<EOF
        config :rustler_precompiled, force_build_all: true
        Code.eval_file(System.get_env("BONFIRE_RUNTIME_CONFIG"))
      EOF
    ''

    # See: justfile#_deps-post-get
    ''
      mkdir -p data
      mkdir -p data/uploads
      mkdir -p priv/static/data
      (cd priv/static/data && ln -fns ../../../data/uploads)
    ''
  ];

  # Note: `preBuild` will not be used when updating,
  # hence it works to have finalAttrs.passthru.mixNixDeps.${dep}.src
  # in there because `deps.nix` will be updated by then.
  preBuild = lib.concatStringsSep "\n" [
    # Explanation: those yarn assets are not real libraries,
    # they can only be built in bonfire-app.
    (lib.concatMapStringsSep "\n" (dep: ''
      rm -rf deps/${dep}
      cp --no-preserve=mode -r \
         ${finalAttrs.passthru.mixNixDeps.${dep}.src} \
         deps/${dep}
      pushd deps/${dep}/assets
      yarnOfflineCache="${finalAttrs.passthru.yarnOfflineCaches.${dep}}" \
      PATH="${lib.makeBinPath [ yarn ]}:$PATH" \
      yarnConfigHook
      popd
    '') (lib.attrNames finalAttrs.passthru.yarnOfflineCaches))

    # Explanation: same but for yarn-berry assets.
    (lib.concatMapStringsSep "\n" (dep: ''
      rm -rf deps/${dep}
      cp --no-preserve=mode -r \
         ${finalAttrs.passthru.mixNixDeps.${dep}.src} \
         deps/${dep}
      pushd deps/${dep}/assets
      yarnOfflineCache="${finalAttrs.passthru.yarnBerryOfflineCaches.${dep}}" \
      missingHashes="${finalAttrs.passthru.yarnBerryOfflineCaches.${dep}.missingHashes}" \
      PATH="${lib.makeBinPath [ finalAttrs.passthru.yarn-berry.yarn-berry-offline ]}:$PATH" \
      yarnBerryConfigHook
      popd
    '') (lib.attrNames finalAttrs.passthru.yarnBerryOfflineCaches))

    # Explanation: call lib/mix/tasks/sync_themes.ex
    # See: justfile#_flavour_install ${finalAttrs.passthru.env.FLAVOUR}
    ''
      mix bonfire.sync_themes
    ''

    # Explanation: install SQL migrations.
    # See: justfile#_ext-migrations-copy
    # which calls:
    #
    # mix bonfire.install.copy_migrations --force
    #
    # implemented in deps/bonfire_common/lib/mix_tasks/install/
    # and callable with:
    #
    # Mix.Tasks.Bonfire.Install.CopyMigrations.copy_all(nil, [{:force, true}, {:to, "priv/repo/migrations/"}])
    #
    # But within the nix setup this fails without my knowing why
    # either by hanging when copying, or by not copying all migrations.
    # Note that all files are also copied, including those with *.exs.wip.
    ''
      rm -rf ./priv/repo/*
      mkdir -p priv/repo/migrations/
      for file in deps/bonfire_*/priv/repo/migrations/*; do
        cp -ft priv/repo/migrations/ "$file"
      done
    ''
  ];

  postBuild = lib.concatStringsSep "\n" [
    # See: justfile#_rel-compile-assets
    ''
      pushd assets
      ${lib.getExe finalAttrs.passthru.yarn-berry.yarn-berry-offline} build
      popd
      mix phx.digest --no-deps-check
    ''
  ];

  # Explanation: only concern buildtime debugging,
  # by being more verbose about what mixRelease
  # and mix do (through MIX_DEBUG=1).
  enableDebugInfo = true;

  meta = {
    description = "An open-source framework for building federated digital spaces where people can gather, interact, and form communities online";
    homepage = "https://bonfirenetworks.org";
    license = with lib.licenses; [
      agpl3Only
      cc0
    ];
    maintainers = with lib.maintainers; [ julm ];
    teams = [ lib.teams.ngi ];
    mainProgram = "bonfire";
  };
})
