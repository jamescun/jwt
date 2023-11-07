package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var publicKey = &cobra.Command{
	Use:   "public",
	Short: "Print Public Key for a JSON Web Token Private Key",

	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, err := readPrivateKey(keyFile)
		if err != nil {
			return err
		}

		pk, ok := privateKey.(interface {
			Public() crypto.PublicKey
		})
		if !ok {
			return fmt.Errorf("private key does not export public key interface")
		}

		bytes, err := x509.MarshalPKIXPublicKey(pk.Public())
		if err != nil {
			return fmt.Errorf("could not marshal public key: %w", err)
		}

		err = pem.Encode(os.Stdout, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		})
		if err != nil {
			return fmt.Errorf("could not write PEM encoded public key: %w", err)
		}

		return nil
	},
}

func readPrivateKey(path string) (crypto.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM-encoded private key")
	} else if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PEM-encoded PRIVATE KEY, got %q", block.Type)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	return privateKey, nil
}
