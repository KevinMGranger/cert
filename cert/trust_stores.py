import subprocess
from pathlib import Path
from enum import IntFlag
import os


class MacOSKeyUsage(IntFlag):
    ANY = -1
    SIGN = 1
    DATA_CRYPT = 2
    KEY_CRYPT = 4
    CERT_SIGN = 8
    REVOC_SIGN = 16
    KEY_EXCHANGE = 32


def macos_trust_cert(cert_path: Path | str, usage: MacOSKeyUsage | None = None):
    # TODO: what is the usage effective default?
    # TODO: can you do multiple policy constraints? policy string? how's that work?
    # TODO: appPath? is that the macos selinux-like thing?
    # TODO: custom keychain? does that matter?
    # TODO: resultType? is that the dropdown in the app?
    cmd = ["security", "add-trusted-cert"]

    if os.getuid() == 0:
        # TODO: allow specifying this manually?
        cmd += ["-d"]

    if usage is not None:
        cmd += ["-u", str(usage.value)]

    cmd += [cert_path]

    # TODO: if debug? special logger?

    subprocess.run(cmd, check=True)
