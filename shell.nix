with import <nixpkgs> { };

let
  liblk = python3Packages.buildPythonPackage rec {
    pname = "liblk";
    version = "master";
    src = fetchFromGitHub {
      owner = "R0rt1z2";
      repo = "liblk";
      rev = "master";
      sha256 = "1nlp59iywbnr1s9qsvzp03qs1zlzr22lw34r9cr15v3wagwyclz5";
    };

    pyproject = true;
    build-system = [ python3Packages.setuptools ];
  };

  lkpatcher = python3Packages.buildPythonPackage rec {
    pname = "lkpatcher";
    version = "local";
    src = ./.;

    pyproject = true;
    build-system = [ python3Packages.setuptools ];

    propagatedBuildInputs = [ liblk ];
  };
in

mkShell {
  name = "lkpatcher";
  buildInputs = [ liblk lkpatcher ];
}
