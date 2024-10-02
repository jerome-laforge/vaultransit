package vaultransit

import (
	"bytes"
	"cmp"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

var _ crypto.Signer = Client{}

type (
	SignReq struct {
		Input              []byte             `json:"input"`
		PreHashed          bool               `json:"prehashed"`
		SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	}

	SignResp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
)

type SignatureAlgorithm string

const (
	PKCS1v15 SignatureAlgorithm = "pkcs1v15"
	PSS      SignatureAlgorithm = "pss"
)

func (c Client) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hashAlgo, err := Hash(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(SignReq{
		Input:              digest,
		PreHashed:          true,
		SignatureAlgorithm: c.SignatureAlgorithm,
	})
	if err != nil {
		return nil, err
	}

	URL := c.URL + "/v1/" + cmp.Or(c.SecretEngine, "transit") + "/sign/" + c.EncryptionKeyName + "/" + hashAlgo
	req, err := http.NewRequest(http.MethodPost, URL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}

	if c.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Namespace)
	}

	httpClient := http.DefaultClient
	if c.HTTPClient != nil {
		httpClient = c.HTTPClient
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() //nolint

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(http.MethodPost + " " + URL + ": " + res.Status)
	}

	signResp := SignResp{}
	if err := json.NewDecoder(res.Body).Decode(&signResp); err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(strings.TrimPrefix(signResp.Data.Signature, "vault:v1:"))
}

func (c Client) Public() crypto.PublicKey {
	panic("not supported")
}
