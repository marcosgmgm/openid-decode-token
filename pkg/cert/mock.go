package cert

import (
	"crypto/rsa"
	"net/http"
)

type ManagerCustomMock struct {
	CertMock      func(kid, realm string) (*Cert, error)
	PublicKeyMock func(cert *Cert) (*rsa.PublicKey, error)
}

func (m ManagerCustomMock) Cert(kid, realm string) (*Cert, error) {
	return m.CertMock(kid, realm)
}

func (m ManagerCustomMock) PublicKey(cert *Cert) (*rsa.PublicKey, error) {
	return m.PublicKeyMock(cert)
}

type HttpClientCustomMock struct {
	DoMock func(req *http.Request) (*http.Response, error)
}

func (h *HttpClientCustomMock) Do(req *http.Request) (*http.Response, error) {
	return h.DoMock(req)
}

