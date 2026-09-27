package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/http2"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func testTLSIdentity(t *testing.T) (*ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestPostQuantumTLS(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		pq, wrongPin, classical, insecure bool
		wantError                         string
	}{
		{name: "hybrid_mtls", pq: true},
		{name: "wrong_pin", pq: true, wrongPin: true, wantError: "different public key"},
		{name: "no_classical_fallback", pq: true, classical: true, wantError: "handshake failure"},
		{name: "insecure_still_requires_pq", pq: true, classical: true, insecure: true, wantError: "handshake failure"},
		{name: "default_accepts_classical", classical: true},
		{name: "draft_group_is_opt_in", wantError: "handshake failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, cert := testTLSIdentity(t)
			clientConfig, err := PrepareTlsConfig(key, &key.PublicKey, cert.Certificate, "localhost", tc.insecure, tc.pq)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wrongPin {
				_, cert = testTLSIdentity(t)
			}
			group := tls.P256Kyber768Draft00
			if tc.classical {
				group = tls.CurveP256
			}
			serverConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{"h3"}, CurvePreferences: []tls.CurveID{group}}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			clientConn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = clientConn.Close() }()
			serverConn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = serverConn.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, server := tls.Client(clientConn, clientConfig), tls.Server(serverConn, serverConfig)
			done := make(chan error, 1)
			go func() { done <- server.HandshakeContext(ctx) }()
			err = client.HandshakeContext(ctx)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("want %q, got %v", tc.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if client.ConnectionState().CurveID != group {
				t.Fatalf("unexpected group: %v", client.ConnectionState().CurveID)
			}
			if len(server.ConnectionState().PeerCertificates) != 1 {
				t.Fatal("missing client certificate")
			}
		})
	}
}

func TestPQVerificationGuards(t *testing.T) {
	key, cert := testTLSIdentity(t)
	config, err := PrepareTlsConfig(key, &key.PublicKey, cert.Certificate, "localhost", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if config.VerifyPeerCertificate(nil, nil) == nil {
		t.Fatal("missing certificate accepted")
	}
	for _, cs := range []tls.ConnectionState{
		{Version: tls.VersionTLS13, CurveID: tls.CurveP256},
		{Version: tls.VersionTLS12, CurveID: tls.P256Kyber768Draft00},
	} {
		if config.VerifyConnection(cs) == nil {
			t.Fatalf("accepted invalid connection state: %+v", cs)
		}
	}
}

// Exercise the real CONNECT clients against local H2/H3 servers, including headers
// and negotiated TLS state. These tests need no Cloudflare account or network access.
func TestConnectTunnelPQMetadata(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, pq := range []bool{false, true} {
			t.Run(fmt.Sprintf("h2=%t/pq=%t", h2, pq), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				key, cert := testTLSIdentity(t)
				clientConfig, err := PrepareTlsConfig(key, &key.PublicKey, cert.Certificate, "localhost", false, pq)
				if err != nil {
					t.Fatal(err)
				}
				group := tls.CurveP256
				if pq {
					group = tls.P256Kyber768Draft00
				}
				serverConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, CurvePreferences: []tls.CurveID{group}, NextProtos: []string{"h3", "h2"}}
				observed := make(chan error, 1)
				h2Handshake := make(chan tls.ConnectionState, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					state := r.TLS
					if h2 {
						// A regular CONNECT omits :scheme, so H2's Request.TLS may be nil.
						cs := <-h2Handshake
						state = &cs
					}
					var check error
					if r.Method != http.MethodConnect || r.Header.Get("pq-enabled") != fmt.Sprint(pq) {
						check = fmt.Errorf("unexpected request: method=%s pq-enabled=%q", r.Method, r.Header.Get("pq-enabled"))
					} else if state == nil || state.CurveID != group {
						check = fmt.Errorf("incorrect negotiated TLS group")
					} else if h2 && r.Header.Get("cf-connect-proto") != "cf-connect-ip" {
						check = fmt.Errorf("missing H2 protocol header")
					} else if !h2 && r.Proto != "cf-connect-ip" {
						check = fmt.Errorf("incorrect H3 extended CONNECT protocol: %s", r.Proto)
					}
					observed <- check
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-ctx.Done()
				})
				var endpoint net.Addr
				if h2 {
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = listener.Close() }()
					endpoint = listener.Addr()
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						c := tls.Server(conn, serverConfig)
						if c.HandshakeContext(ctx) != nil {
							return
						}
						h2Handshake <- c.ConnectionState()
						(&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Context: ctx, Handler: handler})
					}()
				} else {
					udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = udp.Close() }()
					endpoint = udp.LocalAddr()
					server := &http3.Server{TLSConfig: serverConfig, EnableDatagrams: true, Handler: handler}
					defer func() { _ = server.Close() }()
					go func() { _ = server.Serve(udp) }()
				}
				// localhost bypasses ambient HTTP proxy settings in the H2 transport.
				udp, transport, ip, response, err := ConnectTunnel(ctx, clientConfig, &quic.Config{EnableDatagrams: true}, "https://localhost/", endpoint, h2)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = ip.Close() }()
				if udp != nil {
					defer func() { _ = udp.Close() }()
				}
				if transport != nil {
					defer func() { _ = transport.Close() }()
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("status %d", response.StatusCode)
				}
				select {
				case err := <-observed:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				cancel()
			})
		}
	}
}
