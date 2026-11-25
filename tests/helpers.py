import ipaddress
import subprocess

CF = [ipaddress.ip_network(n) for n in ("173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32")]
ORIGIN = "192.0.2.10"


def make_cert(tmp_path, subject, name="ca"):
    key = tmp_path / f"{name}.key"
    crt = tmp_path / f"{name}.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", subject, "-keyout", str(key), "-out", str(crt)],
        check=True, capture_output=True,
    )
    return crt, key

from originveil import net as _net  # noqa: E402
REAL_DIG = _net.dig  # captured before the autouse fixture replaces it
