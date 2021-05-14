package decoder

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/marcosgmgm/openid-decode-token/pkg/cert"
)

type jwtDecoder struct {
	basePath    string
	certsCache  map[string]*cert.Cert
	certManager cert.Manager
}

func NewJwtDecoder(certManager cert.Manager) Decoder {
	return &jwtDecoder{
		certsCache: make(map[string]*cert.Cert),
		certManager: certManager,
	}
}

func (j *jwtDecoder) DecodeAccessTokenClaims(token, realm string, claims jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"]
		rsaPublicKey, err := j.publicKey(kid.(string), realm)
		if err != nil {
			return nil, err
		}
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	})
}

func (j *jwtDecoder) publicKey(kid, realm string) (*rsa.PublicKey, error) {
	c := j.certsCache[kid]
	var err error
	if c == nil {
		c, err = j.certManager.Cert(kid, realm)
		if err != nil {
			return nil, err
		}
		j.certsCache[kid] = c
	}
	return j.certManager.PublicKey(c)
}
