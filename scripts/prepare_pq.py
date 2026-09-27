# /// script
# requires-python = ">=3.11"
# ///
"""Materialize pinned TLS and CONNECT-IP modules with narrow compatibility patches."""
import argparse
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target", type=Path, default=ROOT / "third_party", help="generated module directory")
TARGET = parser.parse_args().target.resolve()
TARGET.mkdir(parents=True, exist_ok=True)

def materialize(module, name):
    info = json.loads(subprocess.check_output(["go", "mod", "download", "-json", module], cwd=ROOT, text=True))
    dest = TARGET / name
    if dest.exists():
        print(f"Already present: {dest}; leaving existing source intact")
        return dest, False
    shutil.copytree(info["Dir"], dest)
    for f in dest.rglob("*"):
        if f.is_file():
            f.chmod(0o644)
    return dest, True

def replace(path, old, new):
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"Patch context missing: {path}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")

tls, fresh = materialize("github.com/metacubex/tls@v0.1.8", "tls")
if fresh:
    replace(tls / "key_schedule.go", '"github.com/metacubex/mlkem"', '"github.com/metacubex/mlkem"\n "github.com/cloudflare/circl/kem"')
    replace(tls / "key_schedule.go", "type keySharePrivateKeys struct {", "type keySharePrivateKeys struct {\n kyber kem.PrivateKey")
    replace(tls / "key_schedule.go", "switch id {", "switch id {\n case P256Kyber768Draft00:\n  return &p256KyberExchange{}, nil")
    replace(tls / "common.go", "type CurveID uint16", "type CurveID uint16\n\nconst P256Kyber768Draft00 CurveID = 0xfe32")
    replace(tls / "common.go", "case X25519MLKEM768,", "case P256Kyber768Draft00, X25519MLKEM768,")
    replace(tls / "common.go", "curvePreferences := defaultCurvePreferences()", "curvePreferences := defaultCurvePreferences()\n if c != nil && slicesContains(c.CurvePreferences, P256Kyber768Draft00) {\n  curvePreferences = append([]CurveID{P256Kyber768Draft00}, curvePreferences...)\n }")
    replace(tls / "common_string.go", "func (i CurveID) String() string {", 'func (i CurveID) String() string {\n if i == P256Kyber768Draft00 { return "P256Kyber768Draft00" }')
    with (tls / "go.mod").open("a", encoding="utf-8") as f:
        f.write("\nrequire github.com/cloudflare/circl v1.6.5\n")
    shutil.copy2(ROOT / "scripts" / "p256kyber.go.txt", tls / "p256kyber.go")

if "hs.keyShareKeys.ecdhe == nil ||" in (tls / "handshake_client_tls13.go").read_text():
    replace(tls / "handshake_client_tls13.go", "hs.keyShareKeys.ecdhe == nil ||", "(hs.keyShareKeys.ecdhe == nil && hs.keyShareKeys.kyber == nil) ||")

cip, fresh = materialize("github.com/Diniboy1123/connect-ip-go@v0.0.0-20260613064811-66cba32d7d33", "connect-ip")
if fresh:
    replace(cip / "go.mod", "github.com/quic-go/quic-go v0.59.0", "github.com/metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4\n github.com/metacubex/http v0.1.7\n github.com/metacubex/tls v0.1.8")
    replace(cip / "go.mod", "github.com/quic-go/qpack", "github.com/metacubex/qpack")
    for f in cip.rglob("*.go"):
        text = f.read_text(encoding="utf-8")
        text = text.replace('"github.com/quic-go/quic-go', '"github.com/metacubex/quic-go')
        text = text.replace('"crypto/tls"', '"github.com/metacubex/tls"')
        text = text.replace('"net/http"', '"github.com/metacubex/http"')
        text = text.replace('"net/http/httptest"', '"github.com/metacubex/http/httptest"')
        text = text.replace('"golang.org/x/net/http2"', '"github.com/metacubex/http/http2"')
        f.write_text(text, encoding="utf-8")
if "http3.ParseCapsule(r)" in (cip / "conn.go").read_text():
    replace(cip / "conn.go", "r := quicvarint.NewReader(c.str)", "r := http3.NewCapsuleParser(c.str)")
    replace(cip / "conn.go", "http3.ParseCapsule(r)", "r.Next()")
for directory in (tls, cip):
    subprocess.run(["gofmt", "-w", str(directory)], check=True)
    subprocess.run(["go", "mod", "edit", "-fmt", "-modfile", str(directory / "go.mod")], cwd=ROOT, check=True)
print("Pinned compatibility modules prepared")
