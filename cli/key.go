package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	genRSA        bool
	genRSAsize    int
	genECDSA      bool
	genECDSAcurve string
	genED25519    bool
	keyFile       string
)

var generateKey = &cobra.Command{
	Use:   "key",
	Short: "Generate a Private Key to sign JSON Web Tokens with",

	PreRunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case genRSA:
			if genECDSA || genED25519 {
				return fmt.Errorf("cannot generate more than one key at a time")
			}

			if genRSAsize < 2048 || genRSAsize > 8192 {
				return fmt.Errorf("--rsa-size must be between 2048 and 8192")
			}

		case genECDSA:
			if genED25519 {
				return fmt.Errorf("cannot generate more than one key at a time")
			}

			if getCurve(genECDSAcurve) == nil {
				return fmt.Errorf("unknown ecdsa curve, must be one of P224, P256, P384 or P521")
			}

		case genED25519:
			// Ed25519 does not have any configuration options.

		default:
			return fmt.Errorf("must specify one of --rsa, --ecdsa or --ed25519")
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var privateKey crypto.PrivateKey

		switch {
		case genRSA:
			key, err := rsa.GenerateKey(rand.Reader, genRSAsize)
			if err != nil {
				return fmt.Errorf("rsa: %w", err)
			}

			privateKey = key

		case genECDSA:
			key, err := ecdsa.GenerateKey(getCurve(genECDSAcurve), rand.Reader)
			if err != nil {
				return fmt.Errorf("ecdsa: %w", err)
			}

			privateKey = key

		case genED25519:
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("ed25519: %w", err)
			}

			privateKey = key
		}

		bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("x509: %w", err)
		}

		output := os.Stdout
		if keyFile != "-" {
			file, err := os.OpenFile(keyFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("could not open output file: %w", err)
			}
			defer file.Close()

			output = file
		}

		err = pem.Encode(output, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		})
		if err != nil {
			return fmt.Errorf("could not write PEM encoded private key: %w", err)
		}

		return nil
	},
}

func init() {
	generateKey.Flags().BoolVar(&genRSA, "rsa", false, "generate an RSA private key for signing")
	generateKey.Flags().IntVar(&genRSAsize, "rsa-size", 2048, "size of RSA private key to generate")
	generateKey.Flags().BoolVar(&genECDSA, "ecdsa", false, "generate an ECDSA private key for signing")
	generateKey.Flags().StringVar(&genECDSAcurve, "ecdsa-curve", "P256", "elliptic curve of ECDSA private key to generate")
	generateKey.Flags().BoolVar(&genED25519, "ed25519", false, "generate an Ed25519 private key for signing")
	generateKey.Flags().StringVar(&keyFile, "output", "key.pem", "write private key to file, or stdout with -")
}

func getCurve(name string) elliptic.Curve {
	switch name {
	case "224", "p224", "P224", "P-224":
		return elliptic.P224()
	case "256", "p256", "P256", "P-256":
		return elliptic.P256()
	case "384", "p384", "P384", "P-384":
		return elliptic.P384()
	case "521", "p521", "P521", "P-521":
		return elliptic.P521()

	default:
		return nil
	}
}
