package cert

import (
	"crypto/rsa"
	"net/http"
)

type Cert struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Manager interface {
	Cert(kid, realm string) (*Cert, error)
	PublicKey(cert *Cert) (*rsa.PublicKey, error)
}