# /// script
# requires-python = ">=3.11"
# ///
"""Run a bounded local SOCKS probe using an existing registration and curl."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, default=Path("usque-pq.exe"))
parser.add_argument("--config", type=Path, required=True)
parser.add_argument("--mode", choices=["socks", "l4-socks"], default="socks")
parser.add_argument("--classical", action="store_true", help="test the default mode without --pq")
parser.add_argument("--http2", action="store_true")
parser.add_argument("--direct", action="store_true", help="clear proxy environment variables for this probe")
args = parser.parse_args()
curl = shutil.which("curl.exe" if os.name == "nt" else "curl")
if not curl:
    parser.error("curl must be installed")
if args.http2 and args.mode != "socks":
    parser.error("--http2 applies to socks only")
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
command = [str(args.binary.resolve()), args.mode, "-c", str(args.config.resolve()), "-b", "127.0.0.1", "-p", str(port)]
if not args.classical:
    command.append("--pq")
if args.http2:
    command.append("--http2")
with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as log:
    environment = dict(os.environ)
    if args.direct:
        environment = {key: value for key, value in environment.items() if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                               env=environment,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise RuntimeError("usque exited before opening the proxy")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError("proxy did not start")
                time.sleep(0.1)
        result = subprocess.run([curl, "--fail", "--silent", "--show-error", "--max-time", "35",
                                 "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{port}",
                                 "https://cloudflare.com/cdn-cgi/trace"], capture_output=True, text=True, timeout=40)
        if result.returncode:
            log.seek(0)
            for line in log:
                if any(marker in line for marker in ("MASQUE PQ handshake:", "Failed to connect", "Tunnel connection failed", "Using HTTP/2 endpoint")):
                    print(line.strip(), file=sys.stderr)
            raise RuntimeError(f"trace failed: {result.stderr.strip()}")
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if fields.get("warp") not in ("on", "plus"):
            raise RuntimeError("trace did not confirm WARP")
        log.seek(0)
        negotiated = [line.strip() for line in log if "MASQUE PQ handshake:" in line]
        if not args.classical and not any("P256Kyber768Draft00" in line for line in negotiated):
            raise RuntimeError("no outer PQ handshake evidence")
        print(json.dumps({"mode": args.mode, "http2": args.http2, "pq_required": not args.classical,
                          "outer_handshake": negotiated, "trace": {key: fields.get(key) for key in ("warp", "colo", "tls", "http", "kex")}}, indent=2))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
