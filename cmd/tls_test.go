package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/metacubex/tls"
	"github.com/spf13/cobra"
)

func TestTunnelCommandsPQFlag(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []*cobra.Command{socksCmd, httpProxyCmd, nativeTunCmd, portFwCmd, l4SocksCmd, l4HTTPProxyCmd} {
		t.Run(command.Name(), func(t *testing.T) {
			flag := command.Flags().Lookup("pq")
			if flag == nil || flag.DefValue != "false" {
				t.Fatal("missing opt-in PQ flag")
			}
			defer func() { _ = command.Flags().Set("pq", "false") }()
			if err := command.Flags().Set("pq", "true"); err != nil {
				t.Fatal(err)
			}
			config, err := prepareTunnelTLSConfig(command, key, &key.PublicKey, nil, "localhost", false)
			if err != nil {
				t.Fatal(err)
			}
			if len(config.CurvePreferences) != 1 || config.CurvePreferences[0] != tls.P256Kyber768Draft00 {
				t.Fatal("PQ flag not applied to TLS")
			}
		})
	}
}
