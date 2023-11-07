package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var (
	kid         string
	aud         []string
	sub         string
	iss         string
	exp         time.Duration
	extraClaims []string
)

var sign = &cobra.Command{
	Use:   "sign claims",
	Short: "Sign creates and signs a JSON Web Token with a Private Key",

	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(aud) < 1 {
			return fmt.Errorf("at least one audience (--aud) is required")
		}

		if sub == "" {
			return fmt.Errorf("--sub is required")
		}

		if iss == "" {
			return fmt.Errorf("--iss is required")
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, err := readPrivateKey(keyFile)
		if err != nil {
			return err
		}

		signer, err := getSigningMethod(privateKey)
		if err != nil {
			return err
		}

		now := time.Now().UTC()

		header := map[string]any{
			"alg": signer.Alg(),
		}

		if kid != "" {
			header["kid"] = kid
		}

		claims := map[string]any{
			"sub": sub,
			"iss": iss,
			"iat": now.Unix(),
			"nbf": now.Unix(),
			"exp": now.Add(exp).Unix(),
		}

		if len(aud) == 1 {
			claims["aud"] = aud[0]
		} else {
			claims["aud"] = aud
		}

		claims, err = appendClaims(claims, extraClaims)
		if err != nil {
			return err
		}

		raw, err := signingString(header, claims)
		if err != nil {
			return err
		}

		sig, err := signer.Sign(raw, privateKey)
		if err != nil {
			return fmt.Errorf("could not sign token: %w", err)
		}

		fmt.Printf("%s.%s\n", raw, base64.RawURLEncoding.EncodeToString(sig))

		return nil
	},
}

func signingString(header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}

	c, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c), nil
}

func getSigningMethod(key crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return &jwt.SigningMethodRSA{
			Name: "RS256",
			Hash: crypto.SHA256,
		}, nil

	case *ecdsa.PrivateKey:
		return &jwt.SigningMethodECDSA{
			Name:      "ES256",
			Hash:      crypto.SHA256,
			KeySize:   32,
			CurveBits: 256,
		}, nil

	case ed25519.PrivateKey:
		return &jwt.SigningMethodEd25519{}, nil

	default:
		return nil, fmt.Errorf("unknown private key type %T", key)
	}
}

func init() {
	sign.Flags().StringVar(&kid, "kid", "", "assign a key id in the header")
	sign.Flags().StringArrayVar(&aud, "aud", nil, "specify one or more audiences for the token")
	sign.Flags().StringVar(&sub, "sub", "", "specify the subject of the token")
	sign.Flags().StringVar(&iss, "iss", "github.com/jamescun/jwt", "specify the issuer for the token")
	sign.Flags().DurationVar(&exp, "exp", 24*time.Hour, "specify the expiration, in s(econds), m(inutes) or (h)ours")
	sign.Flags().StringArrayVar(&extraClaims, "claim", nil, "key=value of additional claims to add, value must be JSON")
}

func appendClaims(dst map[string]any, src []string) (map[string]any, error) {
	for i, v := range src {
		key, value := splitKeyValue(v)
		if value == "" {
			return nil, fmt.Errorf("claims[%d]: claim must have a value", i)
		}

		c := json.RawMessage(value)
		if !json.Valid(c) {
			return nil, fmt.Errorf("claims[%d]: claim value must be valid json", i)
		}

		dst[key] = c
	}

	return dst, nil
}

func splitKeyValue(s string) (string, string) {
	i := strings.IndexByte(s, '=')
	if i > -1 {
		return s[:i], s[i+1:]
	}

	return s, ""
}
