# Local protocol compatibility modules

These source snapshots are included so `go build .` works from a checkout without a preparation step. Their original license files are retained. The root `go.mod` selects these directories with `replace` directives.

| Directory | Upstream base | Changes |
|---|---|---|
| `tls` | `github.com/metacubex/tls v0.1.8` | Optional P256Kyber768Draft00 group using Cloudflare CIRCL v1.6.5; key-share dispatch/state and string/classification support |
| `connect-ip` | `github.com/Diniboy1123/connect-ip-go v0.0.0-20260613064811-66cba32d7d33` | Imports for metacubex TLS/HTTP/QUIC, pinned module requirements, capsule-parser API adaptation |

The draft group is added to supported preferences only when explicitly requested. The TLS fork's default curve list is unchanged. `api.PrepareTlsConfig` selects only this group in PQ mode and checks the negotiated TLS version/group. This keeps PQ mode strict while preserving classical interoperability when the flag is absent.

The adapter is `tls/p256kyber.go`; its template is `scripts/p256kyber.go.txt`. It delegates key generation, serialization, encapsulation and decapsulation to `github.com/cloudflare/circl/kem/hybrid.P256Kyber768Draft00`. Final ML-KEM is not substituted for the older Kyber construction.

To reconstruct the snapshots in a new directory:

```powershell
uv run scripts/prepare_pq.py --target /path/to/empty-directory
```

The script downloads exact upstream versions through Go, applies context-checked changes and formats the result. It preserves existing snapshot directories instead of overwriting them. Normal builds need only Go; Python/uv is used for regeneration and optional live verification.

The QUIC and HTTP forks are pinned in the root module rather than copied here. This dependency change also applies to the tunnel's default mode. Registration API requests and application-facing HTTP proxies continue using standard `net/http`. Future upstream updates must preserve both the PQ and default-mode tests.

If using usque as a dependency in another Go module, the consuming module must also provide the two local replacements (or publish equivalent forks). Go does not inherit dependency modules' `replace` directives. Release binaries and builds from this checkout include the adapted sources normally.
