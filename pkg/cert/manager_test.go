package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

var respConfiguration = "{\"jwks_uri\":\"http://base/test/protocol/openid-connect/certs\"}"
var respCerts = "{\"keys\":[{\"kid\":\"1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc\"," +
	"\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\"," +
	"\"n\":\"h702HSgRKkAOkJrKG0-NZ-LtzhiKpxu401STa_-YmRkrugQKGxfGtIH3EUG965_6MM7NCkG-8q90KbfWuXa9wAgJ" +
	"muWImtvu7k310sNnkBYc3yfc8EThx42OzQ7JklZDe9OT4l-DQ3gRDT0PW2PfMxkSVGbTyhhJ35pJzQ6dGj_bZ9W0oc81H2M6" +
	"xgllMVgK-fnU2EcQ0UlBTzB2RQRLC5WP6kn5ya1d6b2CfMaXVHWAoDDuwFQDyuPMhMmWFlI-yp4OdzvhTym3xEwGvvvn9X3U" +
	"6qMdnee-QzOgCpFW0y_e0-bUelMLF9QcT2LxWFdL0nQhVFEdADcRULCJh55X7Q\"," +
	"\"e\":\"AQAB\",\"x5c\":[\"MIICmzCCAYMCBgF2/ISI1TANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZkZW5uaXMwHhc" +
	"NMjEwMTEzMTYxMDEyWhcNMzEwMTEzMTYxMTUyWjARMQ8wDQYDVQQDDAZkZW5uaXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw" +
	"ggEKAoIBAQCHvTYdKBEqQA6QmsobT41n4u3OGIqnG7jTVJNr/5iZGSu6BAobF8a0gfcRQb3rn/owzs0KQb7yr3Qpt9a5dr3ACA" +
	"ma5Yia2+7uTfXSw2eQFhzfJ9zwROHHjY7NDsmSVkN705PiX4NDeBENPQ9bY98zGRJUZtPKGEnfmknNDp0aP9tn1bShzzUfYzrG" +
	"CWUxWAr5+dTYRxDRSUFPMHZFBEsLlY/qSfnJrV3pvYJ8xpdUdYCgMO7AVAPK48yEyZYWUj7Kng53O+FPKbfETAa+++f1fdTqox" +
	"2d575DM6AKkVbTL97T5tR6UwsX1BxPYvFYV0vSdCFUUR0ANxFQsImHnlftAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACeM9k/z" +
	"71vCuP7l7D9dDt5ly3NjJnsL38Sky0jRflpCDJE9wZer0c06mmc108ybzDpEiWEhnbV5+BQT/EYV/4b0tVj6P2THsmKYFNTrAGi" +
	"Ptp8Kow0QIbvJuxEWlxwVMRLKJfVeQ7UDGt75pr1kjxGCuCEdqwqfTyBD6QRTz5Nk9HtU9XrxQv2r70i9+5g1j3HYZuDot/+qMD" +
	"znrFPF/WS6Hk2cVzep9jAvKCWnICLAJ4d9SsRjN3GvoliPzbPbWn9PNbELrdBLIVTIlCmh8OO/hb2S1pVtd7PgZVZHWcec+292z" +
	"e0Qv3x+T1f2tWUmFbHzv34PEMrWTIfkjZLOMDA=\"],\"x5t\":\"aIYlyLZDg4jL04kci2shPZkZh04\"," +
	"\"x5t#S256\":\"jJp8SlGC0m6-BjqDGdVFaU8lS2PntucDgbQcKvaQsmg\"}]}"

func Test_certManager_PublicKey(t *testing.T) {
	_, pub, _ := generateKeys()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint64(pub.E))
	e := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	type fields struct {
		basePath string
	}
	type args struct {
		cert *Cert
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *rsa.PublicKey
		wantErr bool
	}{
		{
			name: "success",
			fields: fields{
				basePath: "test",
			},
			args: args{
				cert: &Cert{
					Kid: "test",
					N:   n,
					E:   e,
				},
			},
			want:    pub,
			wantErr: false,
		},
		{
			name: "error decode n",
			fields: fields{
				basePath: "test",
			},
			args: args{
				cert: &Cert{
					Kid: "test",
					N:   "test error",
					E:   e,
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error decode e",
			fields: fields{
				basePath: "test",
			},
			args: args{
				cert: &Cert{
					Kid: "test",
					N:   n,
					E:   "test error",
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertManager(tt.fields.basePath, http.DefaultClient)
			got, err := cm.PublicKey(tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func generateKeys() (pk *rsa.PrivateKey, pub *rsa.PublicKey, err error) {
	pk, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub = &pk.PublicKey
	return pk, pub, nil
}

func Test_certManager_Cert(t *testing.T) {
	type fields struct {
		basePath   string
		httpClient HttpClient
	}
	type args struct {
		kid   string
		realm string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       *Cert
		wantErrBol bool
		wantErr    error
	}{
		{
			name: "success",
			fields: fields{
				basePath: "test",
				httpClient: &HttpClientCustomMock{
					DoMock: func(req *http.Request) (*http.Response, error) {
						if req.URL.Path == "test/test/.well-known/openid-configuration" {
							return &http.Response{
								Status:     "ok",
								StatusCode: http.StatusOK,
								Body:       ioutil.NopCloser(bytes.NewBufferString(respConfiguration)),
							}, nil
						}
						if req.URL.Path == "/test/protocol/openid-connect/certs" {
							return &http.Response{
								Status:     "ok",
								StatusCode: http.StatusOK,
								Body:       ioutil.NopCloser(bytes.NewBufferString(respCerts)),
							}, nil
						}
						return nil, nil
					},
				},
			},
			args: args{
				kid:   "1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc",
				realm: "test",
			},
			want: &Cert{
				Kty: "RSA",
				Use: "sig",
				Kid: "1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc",
				X5t: "aIYlyLZDg4jL04kci2shPZkZh04",
				N: "h702HSgRKkAOkJrKG0-NZ-LtzhiKpxu401STa_-YmRkrugQKGxfGtIH3EUG965_6MM7NCkG-8q90KbfWuXa9wAgJmuWIm" +
					"tvu7k310sNnkBYc3yfc8EThx42OzQ7JklZDe9OT4l-DQ3gRDT0PW2PfMxkSVGbTyhhJ35pJzQ6dGj_bZ9W0oc81H2M6xgl" +
					"lMVgK-fnU2EcQ0UlBTzB2RQRLC5WP6kn5ya1d6b2CfMaXVHWAoDDuwFQDyuPMhMmWFlI-yp4OdzvhTym3xEwGvvvn9X3U6q" +
					"Mdnee-QzOgCpFW0y_e0-bUelMLF9QcT2LxWFdL0nQhVFEdADcRULCJh55X7Q",
				E: "AQAB",
				X5c: []string{"MIICmzCCAYMCBgF2/ISI1TANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZkZW5uaXMwHhcNMjEwMTEzMTYx" +
					"MDEyWhcNMzEwMTEzMTYxMTUyWjARMQ8wDQYDVQQDDAZkZW5uaXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQ" +
					"CHvTYdKBEqQA6QmsobT41n4u3OGIqnG7jTVJNr/5iZGSu6BAobF8a0gfcRQb3rn/owzs0KQb7yr3Qpt9a5dr3ACAma5Yia" +
					"2+7uTfXSw2eQFhzfJ9zwROHHjY7NDsmSVkN705PiX4NDeBENPQ9bY98zGRJUZtPKGEnfmknNDp0aP9tn1bShzzUfYzrGCW" +
					"UxWAr5+dTYRxDRSUFPMHZFBEsLlY/qSfnJrV3pvYJ8xpdUdYCgMO7AVAPK48yEyZYWUj7Kng53O+FPKbfETAa+++f1fdTq" +
					"ox2d575DM6AKkVbTL97T5tR6UwsX1BxPYvFYV0vSdCFUUR0ANxFQsImHnlftAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACe" +
					"M9k/z71vCuP7l7D9dDt5ly3NjJnsL38Sky0jRflpCDJE9wZer0c06mmc108ybzDpEiWEhnbV5+BQT/EYV/4b0tVj6P2THsm" +
					"KYFNTrAGiPtp8Kow0QIbvJuxEWlxwVMRLKJfVeQ7UDGt75pr1kjxGCuCEdqwqfTyBD6QRTz5Nk9HtU9XrxQv2r70i9+5g1j" +
					"3HYZuDot/+qMDznrFPF/WS6Hk2cVzep9jAvKCWnICLAJ4d9SsRjN3GvoliPzbPbWn9PNbELrdBLIVTIlCmh8OO/hb2S1pVtd" +
					"7PgZVZHWcec+292ze0Qv3x+T1f2tWUmFbHzv34PEMrWTIfkjZLOMDA="},
			},
			wantErr: nil,
			wantErrBol: false,
		},
		{
			name: "error request configuration",
			fields: fields{
				basePath: "test",
				httpClient: &HttpClientCustomMock{
					DoMock: func(req *http.Request) (*http.Response, error) {
						if req.URL.Path == "test/test/.well-known/openid-configuration" {
							return nil, errors.New("error configuration")
						}
						return nil, nil
					},
				},
			},
			args: args{
				kid:   "1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc",
				realm: "test",
			},
			want: nil,
			wantErr: errors.New("error configuration"),
			wantErrBol: true,
		},
		{
			name: "request configuration not found",
			fields: fields{
				basePath: "test",
				httpClient: &HttpClientCustomMock{
					DoMock: func(req *http.Request) (*http.Response, error) {
						if req.URL.Path == "test/test/.well-known/openid-configuration" {
							return &http.Response{
								Status:     "not found",
								StatusCode: http.StatusNotFound,
							}, nil
						}
						return nil, nil
					},
				},
			},
			args: args{
				kid:   "1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc",
				realm: "test",
			},
			want: nil,
			wantErr: errors.New("error get configuration. Response code: 404. Url: test/test/.well-known/openid-configuration"),
			wantErrBol: true,
		},
		{
			name: "error request certs",
			fields: fields{
				basePath: "test",
				httpClient: &HttpClientCustomMock{
					DoMock: func(req *http.Request) (*http.Response, error) {
						if req.URL.Path == "test/test/.well-known/openid-configuration" {
							return &http.Response{
								Status:     "ok",
								StatusCode: http.StatusOK,
								Body:       ioutil.NopCloser(bytes.NewBufferString(respConfiguration)),
							}, nil
						}
						if req.URL.Path == "/test/protocol/openid-connect/certs" {
							return nil, errors.New("error certs")
						}
						return nil, nil
					},
				},
			},
			args: args{
				kid:   "1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc",
				realm: "test",
			},
			want: nil,
			wantErr: errors.New("error certs"),
			wantErrBol: true,
		},
		{
			name: "request certs not found",
			fields: fields{
				basePath: "test",
				httpClient: &HttpClientCustomMock{
					DoMock: func(req *http.Request) (*http.Response, error) {
						if req.URL.Path == "test/test/.well-known/openid-configuration" {
							return &http.Response{
								Status:     "ok",
								StatusCode: http.StatusOK,
								Body:       ioutil.NopCloser(bytes.NewBufferString(respConfiguration)),
							}, nil
						}
						if req.URL.Path == "/test/protocol/openid-connect/certs" {
							return &http.Response{
								Status:     "not found",
								StatusCode: http.StatusNotFound,
							}, nil
						}
						return nil, nil
					},
				},
			},
			args: args{
				kid:   "1h_MHweQR-g8osNYJvhd-FZ4s2lJ52PRm0G68jsuLPc",
				realm: "test",
			},
			want: nil,
			wantErr: errors.New("error get keys. Response code: 404. Url: http://base/test/protocol/openid-connect/certs"),
			wantErrBol: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertManager(tt.fields.basePath, tt.fields.httpClient)
			got, err := cm.Cert(tt.args.kid, tt.args.realm)
			if (err != nil) != tt.wantErrBol {
				t.Errorf("Cert() error = %v, wantErr %v", err, tt.wantErrBol)
				return
			}
			if tt.wantErrBol {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("Cert() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Cert() got = %v, want %v", got, tt.want)
			}
		})
	}
}
