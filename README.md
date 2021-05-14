Decode JWT Token
================================

Use this lib to validate and decode JWT Tokens

## Install
```bash
go get github.com/marcosgmgm/openid-decode-token
```

## Example
```go
package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/marcosgmgm/openid-decode-token/pkg/cert"
	"github.com/marcosgmgm/openid-decode-token/pkg/decoder"
	"log"
	"net/http"
)

func main() {
	manager := cert.NewCertManager("http://idm.base.path", http.DefaultClient)
	decode := decoder.NewJwtDecoder(manager)
	claims := jwt.MapClaims{}
	token, err := decode.DecodeAccessTokenClaims("your jwt token", "realm", claims)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(token)
	fmt.Println(claims) 
}
```
