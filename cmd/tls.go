package cmd

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/Diniboy1123/usque/api"
	"github.com/metacubex/tls"
	"github.com/spf13/cobra"
)

func prepareTunnelTLSConfig(cmd *cobra.Command, privateKey *ecdsa.PrivateKey, peerKey *ecdsa.PublicKey, cert [][]byte, sni string, insecure bool) (*tls.Config, error) {
	pq, err := cmd.Flags().GetBool("pq")
	if err != nil {
		return nil, fmt.Errorf("read PQ mode: %w", err)
	}
	return api.PrepareTlsConfig(privateKey, peerKey, cert, sni, insecure, pq)
}
