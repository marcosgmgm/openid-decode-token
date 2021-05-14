package decoder

import "github.com/dgrijalva/jwt-go"

type Decoder interface {
	DecodeAccessTokenClaims(token, realm string, claims jwt.Claims) (*jwt.Token, error)
}
