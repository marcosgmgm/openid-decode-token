package cert

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

const (
	configurationURLPattern = "%s/%s/.well-known/openid-configuration"
	urlSeparator  string = "/"
)

type certManager struct {
	basePath string
	httpClient HttpClient
}

func NewCertManager(basePath string, httpClient HttpClient) Manager {
	return certManager{
		basePath:    strings.TrimRight(basePath, urlSeparator),
		httpClient: httpClient,
	}
}

func (cm certManager) PublicKey(cert *Cert) (*rsa.PublicKey, error) {
	decN, err := base64.RawURLEncoding.DecodeString(cert.N)
	if err != nil {
		return nil, err
	}

	nInt := big.NewInt(0)
	nInt.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(cert.E)
	if err != nil {
		return nil, err
	}

	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}

	eReader := bytes.NewReader(eBytes)
	var eInt uint64
	err = binary.Read(eReader, binary.BigEndian, &eInt)
	if err != nil {
		return nil, err
	}

	pKey := rsa.PublicKey{N: nInt, E: int(eInt)}
	return &pKey, nil
}


func (cm certManager) Cert(kid, realm string) (*Cert, error) {
	//Get configurations
	urlConfiguration := fmt.Sprintf(configurationURLPattern, cm.basePath, realm)
	reqConf, _ := http.NewRequest(http.MethodGet, urlConfiguration, nil)
	resp, err := cm.httpClient.Do(reqConf)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("error get configuration. Response code: %d. Url: %s", resp.StatusCode, urlConfiguration)
	}
	type ConfigRealm struct {
		URLKeys string `json:"jwks_uri"`
	}
	var jr ConfigRealm
	defer resp.Body.Close()
	if err = json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return nil, err
	}
	//Get keys
	reqCerts, _ := http.NewRequest(http.MethodGet, jr.URLKeys, nil)
	respKeys, err := cm.httpClient.Do(reqCerts)
	if err != nil {
		return nil, err
	}
	if respKeys.StatusCode < 200 || respKeys.StatusCode > 299 {
		return nil, fmt.Errorf("error get keys. Response code: %d. Url: %s", respKeys.StatusCode, jr.URLKeys)
	}
	defer respKeys.Body.Close()
	type kResp struct {
		Keys []Cert `json:"keys"`
	}
	var kr kResp
	if err = json.NewDecoder(respKeys.Body).Decode(&kr); err != nil {
		return nil, err
	}
	cert := Cert{}
	for _, k := range kr.Keys {
		if k.Kid == kid {
			cert = k
			break
		}
	}
	if len(cert.E) == 0 {
		return nil, errors.New("no has key")
	}
	return &cert, nil
}

