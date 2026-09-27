# Post-quantum MASQUE mode

## Usage

Add `--pq` to any tunnel/proxy command:

```shell
usque socks --pq -b 127.0.0.1 -p 1080
usque l4-socks --pq -b 127.0.0.1 -p 1080
usque http-proxy --pq -b 127.0.0.1 -p 8000
```

`nativetun`, `portfw`, and `l4-http-proxy` also accept the flag. The full IP modes can combine it with `--http2`; L4 modes use HTTP/3. Existing enrollment and license configuration are reused. This option does not enroll another device or store a license key.

With a local SOCKS listener running, verify traffic with:

```shell
curl --noproxy "" --socks5-hostname 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

A successful outer handshake is logged as:

```text
MASQUE PQ handshake: TLS=0x304 group=P256Kyber768Draft00 ALPN=h3
```

The trace should report `warp=on` or `warp=plus`. Its `kex` field describes the HTTPS connection inside the tunnel. Read the usque handshake log to identify the outer MASQUE key exchange.

## Behavior

- PQ mode requires TLS 1.3 and the hybrid **P256Kyber768Draft00** group (`0xfe32` / 65074).
- It offers no classical alternative. A server without this group fails the handshake; retries and reconnects retain the same requirement.
- HTTP/3 CONNECT-IP, HTTP/2 CONNECT-IP, and L4 CONNECT requests send `pq-enabled: true` in PQ mode and `false` otherwise. The header is metadata; TLS negotiation provides the cryptographic evidence.
- The enrolled endpoint key is still pinned. `--insecure` retains its existing meaning of skipping that pin, but it does not disable the PQ requirement.
- With no `--pq`, the draft group is not added to the TLS preferences and the client can use classical key exchange.

The key agreement combines P-256 with the historical Kyber768 draft used by this WARP endpoint. It is not the final ML-KEM group. Certificate authentication remains ECDSA. This change makes no FIPS validation claim.

## Implementation

`cmd/tls.go` reads the opt-in flag and passes it into `api.PrepareTlsConfig`. The resulting TLS configuration carries the singleton curve preference and a negotiated-state verification callback. Shared CONNECT setup derives its metadata from that preference, including on reconnects; L4 uses the same TLS builder.

Go's standard TLS does not expose this historical group. The tunnel uses pinned metacubex TLS/QUIC/HTTP libraries, with a small CIRCL adapter in the checked-in TLS snapshot. CONNECT-IP is adapted to the matching HTTP/QUIC types and capsule parser. See [dependency provenance](../third_party/README.md). Ordinary builds and the Docker build use these local snapshots automatically.

The group selection is supported by local reverse-engineering of `warp-svc.exe` version 2026.7.1376.0, SHA-256 `00cb393a8f04ec04be0d656b8d7d86628bda0bf457489eb89f2588977f16b2f2`. At preferred-image VA `0x1419a6c80`, the TLS builder appends group 65074 when its PQ setting is enabled, followed by classical groups 23, 24 and 25. This implementation deliberately requires the hybrid group when requested. It was then checked against live Cloudflare service connections.

## Verification

Local tests exercise actual TLS handshakes and HTTP/2/HTTP/3 CONNECT clients, covering:

- Hybrid negotiation with client certificates.
- Rejection of a wrong pinned key, absent certificate, classical-only peer, and wrong TLS version.
- PQ enforcement with `--insecure`.
- Default-mode classical interoperability and absence of the draft offer by default.
- CONNECT headers and negotiated groups for PQ on/off over H2 and H3.
- Flag wiring for all six tunnel/proxy commands.

Run:

```shell
go test -count=1 ./...
go vet ./...
```

An optional bounded probe launches a temporary loopback SOCKS listener, requests the trace with curl, prints only selected result fields, and stops its own child process:

```powershell
go build -o usque-pq.exe .
uv run scripts/verify_pq.py --binary ./usque-pq.exe --config /path/to/config.json
uv run scripts/verify_pq.py --binary ./usque-pq.exe --config /path/to/config.json --mode l4-socks
uv run scripts/verify_pq.py --binary ./usque-pq.exe --config /path/to/config.json --classical
```

`--http2` tests full IP mode over TCP; `--direct` clears proxy environment variables only in the temporary child process. The script reuses the supplied registration and does not modify its configuration. It requires curl and does not install a system tunnel.

Live checks on Windows amd64 on 2026-09-28 returned `warp=plus`, `colo=LAX` for PQ SOCKS, PQ L4 SOCKS, and default SOCKS. The PQ runs logged TLS 1.3, P256Kyber768Draft00 and `h3`. The inner HTTPS request used X25519 in these curl runs, demonstrating that inner and outer key agreement are separate.

The package tests, `go vet`, and the configured golangci-lint v2.11.4 checks passed under Go 1.26.3. Builds also passed for Linux amd64 and Windows 386 with CGO disabled. A fresh run of the preparation script reproduced all 202 dependency snapshot files byte-for-byte.

HTTP/2 interoperability is covered locally. The live HTTP/2 check through the host's proxy environment failed the enrolled server-key pin check; it was not treated as successful and the pin was not bypassed. A direct check without proxy environment variables encountered TCP resets/timeouts at `162.159.198.2:443`. Live H2 success is therefore unverified on this host.
