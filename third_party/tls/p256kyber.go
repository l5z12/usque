// Research compatibility adapter for WARP's historical TLS group 0xfe32.
// Cryptographic primitives and hybrid serialization come from Cloudflare CIRCL.
package tls

import (
	"github.com/cloudflare/circl/kem/hybrid"
	"io"
)

type p256KyberExchange struct{}

func (*p256KyberExchange) keyShares(random io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	scheme := hybrid.P256Kyber768Draft00()
	seed := make([]byte, scheme.SeedSize())
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, nil, err
	}
	pub, priv := scheme.DeriveKeyPair(seed)
	encoded, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{kyber: priv}, []keyShare{{P256Kyber768Draft00, encoded}}, nil
}

func (*p256KyberExchange) clientSharedSecret(priv *keySharePrivateKeys, share []byte) ([]byte, error) {
	return hybrid.P256Kyber768Draft00().Decapsulate(priv.kyber, share)
}

func (*p256KyberExchange) serverSharedSecret(random io.Reader, share []byte) ([]byte, keyShare, error) {
	scheme := hybrid.P256Kyber768Draft00()
	pub, err := scheme.UnmarshalBinaryPublicKey(share)
	if err != nil {
		return nil, keyShare{}, err
	}
	seed := make([]byte, scheme.EncapsulationSeedSize())
	if _, err = io.ReadFull(random, seed); err != nil {
		return nil, keyShare{}, err
	}
	ciphertext, secret, err := scheme.EncapsulateDeterministically(pub, seed)
	return secret, keyShare{P256Kyber768Draft00, ciphertext}, err
}
