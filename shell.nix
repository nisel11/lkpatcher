with import <nixpkgs> { };

let
  liblk = python3Packages.buildPythonPackage rec {
    pname = "liblk";
    version = "master";
    src = fetchFromGitHub {
      owner = "R0rt1z2";
      repo = "liblk";
      rev = "master";
      sha256 = "0ib1x4sqabvbhz78akwyrfcmw86yyqg7vlicdi4swvjgyqx1amkv";
    };

    pyproject = true;
    build-system = [ python3Packages.setuptools ];
    propagatedBuildInputs = [ python3Packages.pyasn1 ];
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
