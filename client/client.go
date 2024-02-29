package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	dpopjwt "github.com/thiagocamargodacosta/dpopjwt/v0"
)

func Main() {

	key, jwk, err := CreateKey()

	if err != nil {
		log.Fatal(err)
		return
	}

	nonce, err := GetNonce(jwk, "http://localhost:8001/nonce")

	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("nonce:", nonce)

	token, err := CreateDPoPProof(key, jwk, nonce, "http://localhost:8001/token", "GET")

	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("token:", token.String())

	access_token, err := CreateDPoPBoundTokenRequest(*token, "http://localhost:8001/token")

	if err != nil {
		log.Fatal("Error while requesting access token:", err)
	}

	fmt.Println("body:", access_token)

}

func CreateDPoPBoundTokenRequest(token dpopjwt.Token, url string) (string, error) {

	client := &http.Client{}

	req, err := http.NewRequest("POST", url, nil)

	if err != nil {
		log.Fatal(err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", token.String())

	resp, err := client.Do(req)

	if err != nil {
		log.Fatal("Error sending request:", err)
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 200 {

		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(resp.Body)

		if err != nil {
			log.Fatal("Error reading response body:", err)
			return "", err
		}

		return buf.String(), nil
	}

	return "", errors.New("unable to generate access token")
}

func CreateDPoPProof(key *ecdsa.PrivateKey, jwk dpopjwt.JWK, nonce, url, htm string) (*dpopjwt.Token, error) {

	signer, err := dpopjwt.NewSignerES(dpopjwt.ES256, key)

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	jkt, _ := dpopjwt.Jkt(jwk)

	claims := &dpopjwt.RegisteredClaims{
		Jti:   uuid.NewString(),
		Htm:   htm,
		Htu:   url,
		Iat:   dpopjwt.NewNumericDate(time.Now()),
		Nonce: nonce,
		Cnf:   dpopjwt.Cnf{Jkt: jkt},
	}

	opts := []dpopjwt.BuilderOption{
		dpopjwt.WithJWK(jwk),
		dpopjwt.WithTyp("dpop+jwt"),
	}

	builder := dpopjwt.NewBuilder(signer, opts...)

	token, err := builder.Build(claims)

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return token, nil
}

func GetNonce(jwk dpopjwt.JWK, url string) (string, error) {

	client := &http.Client{}

	req, err := http.NewRequest("POST", url, nil)

	if err != nil {
		log.Fatal(err)
		return "", err
	}

	jkt, _ := dpopjwt.Jkt(jwk)

	if err != nil {
		log.Fatal(err)
		return "", err
	}

	req.Header.Set("jkt", jkt)

	resp, err := client.Do(req)

	if err != nil {
		log.Fatal("Error sending request:", err)
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return resp.Header.Values("DPoP-Nonce")[0], nil
	}

	return "", errors.New("empty value in DPoP-Nonce header")

}

func CreateKey() (*ecdsa.PrivateKey, dpopjwt.JWK, error) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		log.Fatal(err)
		return nil, dpopjwt.JWK{}, err
	}

	jwk, err := dpopjwt.ECDSAToJWK(&key.PublicKey)

	if err != nil {
		log.Fatal(err)
		return nil, dpopjwt.JWK{}, err
	}

	return key, jwk, nil
}
