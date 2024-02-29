package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	dpopjwt "github.com/thiagocamargodacosta/dpopjwt/v0"
)

var ErrorNoSuchKey = errors.New("no such key")

type store struct {
	m map[string]string
	sync.RWMutex
}

var nonces = store{
	m: make(map[string]string),
}

type AccessTokenResponse struct {

	// Stores the DPoP-bound access token
	AccessToken string `json:"access_token"`
	// Stores the access token type
	TokenType string `json:"token_type"`
	// Stores when the token will expire
	Expires *dpopjwt.NumericDate `json:"expires_in"`
	// Stores the refresh token
	RefreshToken string `json:"refresh_token,omitempty"`
}

func nonceHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		log.Printf("error=\"Invalid Request\" path=%s method=%s", r.URL.Path, r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	value := r.Header.Values("jkt")[0]

	if value == "" {
		http.Error(w, "No 'jkt' provided in request header", http.StatusBadRequest)
	} else {

		nonce := dpopjwt.GenerateNonce(24)

		nonces.Lock()
		nonces.m[value] = nonce
		nonces.Unlock()

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("DPoP-Nonce", nonce)
		w.WriteHeader(http.StatusCreated)

	}

}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		log.Printf("error=\"Invalid Request\" path=%s method=%s", r.URL.Path, r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	response := AccessTokenResponse{
		AccessToken:  "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
		TokenType:    "DPoP",
		Expires:      dpopjwt.NewNumericDate(time.Now()),
		RefreshToken: "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g",
	}

	responseJSON, err := json.MarshalIndent(response, "", " ")

	if err != nil {
		http.Error(w, "Error while encoding response", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)
}
