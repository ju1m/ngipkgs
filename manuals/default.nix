{
  callPackage,
  lib,
  python3,
  stdenv,
  texlive,
  version,
  projects,
  nixosOptionsDoc,
  modulesPath,
  pkgs,
  ...
}:
stdenv.mkDerivation {
  name = "NGIpkgs-manuals";
  src =
    with lib.fileset;
    toSource {
      root = ../.;
      fileset = unions [
        (fileFilter (
          file:
          lib.any file.hasExt [
            "md"
            "nix"
          ]
        ) ../.)
        ./Makefile
        ./_ext
        ./_redirects
        ./_static
        ./_templates
        ./conf.py
        ./favicon.png
        ./netlify.toml
        ./robots.txt
        ../profiles
        ../projects
      ];
    };
  nativeBuildInputs = [
    python3.pkgs.linkify-it-py
    python3.pkgs.myst-parser
    python3.pkgs.sphinx
    #python3.pkgs.sphinx-argparse
    #python3.pkgs.sphinx-autoapi
    #python3.pkgs.sphinx-autobuild
    #python3.pkgs.sphinx-autodoc-typehints
    #python3.pkgs.sphinx-autodoc2
    #python3.pkgs.sphinx-automodapi
    #python3.pkgs.sphinx-basic-ng
    #python3.pkgs.sphinx-better-theme
    python3.pkgs.sphinx-book-theme
    #python3.pkgs.sphinx-click
    #python3.pkgs.sphinx-codeautolink
    #python3.pkgs.sphinx-comments
    python3.pkgs.sphinx-copybutton
    python3.pkgs.sphinx-design
    #python3.pkgs.sphinx-external-toc
    #python3.pkgs.sphinx-favicon
    #python3.pkgs.sphinx-fortran
    #python3.pkgs.sphinx-hoverxref
    #python3.pkgs.sphinx-inline-tabs
    #python3.pkgs.sphinx-intl
    #python3.pkgs.sphinx-issues
    #python3.pkgs.sphinx-jinja
    #python3.pkgs.sphinx-jinja2-compat
    #python3.pkgs.sphinx-jquery
    #python3.pkgs.sphinx-jupyterbook-latex
    #python3.pkgs.sphinx-last-updated-by-git
    #python3.pkgs.sphinx-lv2-theme
    #python3.pkgs.sphinx-markdown-builder
    #python3.pkgs.sphinx-markdown-parser
    #python3.pkgs.sphinx-markdown-tables
    #python3.pkgs.sphinx-material
    #python3.pkgs.sphinx-mdinclude
    #python3.pkgs.sphinx-multitoc-numbering
    #python3.pkgs.sphinx-multiversion
    python3.pkgs.sphinx-notfound-page
    #python3.pkgs.sphinx-prompt
    #python3.pkgs.sphinx-pytest
    #python3.pkgs.sphinx-remove-toctrees
    #python3.pkgs.sphinx-reredirects
    #python3.pkgs.sphinx-rtd-dark-mode
    #python3.pkgs.sphinx-rtd-theme
    #python3.pkgs.sphinx-serve
    python3.pkgs.sphinx-sitemap
    #python3.pkgs.sphinx-tabs
    #python3.pkgs.sphinx-testing
    #python3.pkgs.sphinx-thebe
    #python3.pkgs.sphinx-tippy
    #python3.pkgs.sphinx-togglebutton
    #python3.pkgs.sphinx-toolbox
    #python3.pkgs.sphinx-version-warning
    #python3.pkgs.sphinx-versions
    python3.pkgs.pkgs.perl
    # Explanation: generated with nix run github:rgri/tex2nix -- *.tex *.sty
    (callPackage ./tex-env.nix {
      extraTexPackages = {
        inherit (texlive) latexmk gnu-freefont;
      };
    })
  ];
  patchPhase = ''
    substituteInPlace manuals/index.md \
      --replace-fail '@MANUALS_VERSION@' "${version}"
  '';
  buildPhase = ''
    pushd manuals
    make html
    make singlehtml
    make latexpdf
    popd
  '';
  installPhase = ''
    cp -R build/html $out/
    cp -R build/singlehtml $out/
    cp build/latex/Nix@NGI_manuals.pdf $out/
    cp netlify.toml $out/
  '';
  passthru = {
    optionsDoc = nixosOptionsDoc {
      options =
        lib.flip builtins.removeAttrs [ "_module" ]
          (lib.evalModules {
            class = "nixos";
            specialArgs = {
              inherit pkgs modulesPath;
            };
            modules = [
              {
                config = {
                  # Explanation: do not check anything
                  # because NixOS options are not included.
                  # See also comment in NixOS' `noCheckForDocsModule`.
                  _module.check = false;
                };

                imports = lib.flatten (
                  lib.attrValues (
                    lib.mapAttrs (
                      name: project:
                      lib.attrValues (
                        lib.filterAttrs (_: module: module != null) (
                          lib.mapAttrs (n: p: p.module or null) (project.nixos.modules.services or { })
                        )
                      )
                    ) projects
                  )
                );
                #options = (import projects/types.nix { inherit lib; }).options;
                #inherit (self.project-utils.eval-projects) options;
              }
            ];
          }).options;
    };
  };
}
