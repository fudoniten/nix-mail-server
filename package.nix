{ lib
, python3
, stdenv
}:

stdenv.mkDerivation rec {
  pname = "mail-monitor";
  version = "1.0.0";

  src = ./.;

  nativeBuildInputs = [ python3 ];

  installPhase = ''
    mkdir -p $out/bin
    cp ${./mail-monitor.py} $out/bin/mail-monitor
    chmod +x $out/bin/mail-monitor

    # Replace shebang with nix python
    substituteInPlace $out/bin/mail-monitor \
      --replace "#!/usr/bin/env python3" "#!${python3}/bin/python3"
  '';

  meta = with lib; {
    description = "Mail server monitoring tool with ntfy.sh notifications";
    homepage = "https://github.com/fudoniten/nix-mail-server";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.linux;
  };
}
