Example:

```go
func main() {
	c := Client{
		Config: Config{
			URL:                "https://somewhe.re",
			EncryptionKeyName:  "myEncryptionKeyName",
			SignatureAlgorithm: PKCS1v15,
		},
	}

	sign, err := signer.Sign(rand.Reader, []byte("my message"), crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
}
```
