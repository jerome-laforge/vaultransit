package vaultransit

import (
	"crypto"
	"errors"
	"net/http"
)

type Config struct {
	URL                string
	SecretEngine       string // SecretEngine the default value is transit
	EncryptionKeyName  string
	SignatureAlgorithm SignatureAlgorithm
	Token              string
	Namespace          string
}

type Client struct {
	Config
	HTTPClient *http.Client
}

func Hash(hash crypto.Hash) (string, error) {
	switch hash {
	case crypto.SHA224:
		return "sha2-224", nil
	case crypto.SHA256:
		return "sha2-256", nil
	case crypto.SHA384:
		return "sha2-384", nil
	case crypto.SHA512:
		return "sha2-512", nil
	default:
		return "", errors.New("unsupported hash algorithm")
	}
}

const (
	XVaultToken     = "X-Vault-Token"
	XVaultNamespace = "X-Vault-Namespace"
)
