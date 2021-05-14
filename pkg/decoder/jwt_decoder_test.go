package decoder

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/marcosgmgm/openid-decode-token/pkg/cert"
	"reflect"
	"testing"
	"time"
)

func Test_jwtDecoder_DecodeAccessTokenClaims(t *testing.T) {
	pk, pub, _ := generateKeys()
	tokenString := generateToken(pk, "Can be anything", time.Minute)
	type fields struct {
		basePath    string
		certManager cert.Manager
	}
	type args struct {
		token  string
		realm  string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantToken    string
		wantClainData string
		wantErr error
	}{
		{
			name:    "success",
			fields:  fields{
				basePath:    "test",
				certManager: cert.ManagerCustomMock{
					CertMock: func(kid, realm string) (*cert.Cert, error) {
						return &cert.Cert{Kid: kid}, nil
					},
					PublicKeyMock: func(cert *cert.Cert) (*rsa.PublicKey, error) {
						return pub, nil
					},
				},
			},
			args:    args{
				token:  tokenString,
				realm:  "test",
			},
			wantToken:   tokenString,
			wantClainData: "Can be anything",
			wantErr: nil,
		},
		{
			name:    "error get cert",
			fields:  fields{
				basePath:    "test",
				certManager: cert.ManagerCustomMock{
					CertMock: func(kid, realm string) (*cert.Cert, error) {
						return nil, errors.New("error cert")
					},
					PublicKeyMock: func(cert *cert.Cert) (*rsa.PublicKey, error) {
						return pub, nil
					},
				},
			},
			args:    args{
				token:  tokenString,
				realm:  "test",
			},
			wantErr: errors.New("error cert"),
		},
		{
			name:    "error get public key",
			fields:  fields{
				basePath:    "test",
				certManager: cert.ManagerCustomMock{
					CertMock: func(kid, realm string) (*cert.Cert, error) {
						return &cert.Cert{Kid: kid}, nil
					},
					PublicKeyMock: func(cert *cert.Cert) (*rsa.PublicKey, error) {
						return nil, errors.New("error public key")
					},
				},
			},
			args:    args{
				token:  tokenString,
				realm:  "test",
			},
			wantErr: errors.New("error public key"),
		},
		{
			name:    "invalid token",
			fields:  fields{
				basePath:    "test",
				certManager: cert.ManagerCustomMock{
					CertMock: func(kid, realm string) (*cert.Cert, error) {
						return &cert.Cert{Kid: kid}, nil
					},
					PublicKeyMock: func(cert *cert.Cert) (*rsa.PublicKey, error) {
						return pub, nil
					},
				},
			},
			args:    args{
				token:  generateInvalidToken("Can be anything"),
				realm:  "test",
			},
			wantErr: errors.New("token contains an invalid number of segments"),
		},
		{
			name:    "invalid signing method",
			fields:  fields{
				basePath:    "test",
				certManager: cert.ManagerCustomMock{
					CertMock: func(kid, realm string) (*cert.Cert, error) {
						return &cert.Cert{Kid: kid}, nil
					},
					PublicKeyMock: func(cert *cert.Cert) (*rsa.PublicKey, error) {
						return pub, nil
					},
				},
			},
			args:    args{
				token:  generateTokenInvalidSigningMethod("Can be anything", time.Minute),
				realm:  "test",
			},
			wantErr: errors.New("unexpected signing method: none"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := NewJwtDecoder(tt.fields.basePath, tt.fields.certManager)
			claims := jwt.MapClaims{}
			got, err := j.DecodeAccessTokenClaims(tt.args.token, tt.args.realm, claims)
			if err != nil && tt.wantErr == nil {
				t.Errorf("DecodeAccessTokenClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("DecodeAccessTokenClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got.Raw, tt.wantToken) {
					t.Errorf("DecodeAccessTokenClaims() got = %v, want %v", got, tt.wantToken)
				}
				if claims["dat"].(string) != tt.wantClainData {
					t.Errorf("DecodeAccessTokenClaims() gotClaims = %v, want %v", claims["dat"], tt.wantClainData)
				}
			}
		})
	}
}


func generateKeys() (pk *rsa.PrivateKey, pub *rsa.PublicKey, err error){
	pk, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub = &pk.PublicKey
	return pk, pub, nil
}

func generateToken(pk *rsa.PrivateKey, content interface{}, ttl time.Duration) string {
	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["dat"] = content             // Our custom data.
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodRS256.Alg(),
			"kid" : "kid",
		},
		Claims: claims,
		Method: jwt.SigningMethodRS256,
	}
	t, _ :=  token.SignedString(pk)
	return t
}

func generateInvalidToken(content interface{}) string {
	claims := make(jwt.MapClaims)
	claims["dat"] = content             // Our custom data.
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"kid" : "kid",
		},
		Claims: claims,
	}
	t, _ :=  token.SigningString()
	return t
}

func generateTokenInvalidSigningMethod(content interface{}, ttl time.Duration) string {
	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["dat"] = content             // Our custom data.
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodNone.Alg(),
			"kid" : "kid",
		},
		Claims: claims,
		Method: jwt.SigningMethodNone,
	}
	t, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	return t
}