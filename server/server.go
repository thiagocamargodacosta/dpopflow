package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	dpopjwt "github.com/thiagocamargodacosta/dpopjwt/v0"
)

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

var nonces = make(map[string]string)

func Serve() {

	PORT := ":8001"

	http.HandleFunc("/nonce", nonceHandler)
	http.HandleFunc("/token", tokenHandler)

	err := http.ListenAndServe(PORT, nil)

	if err != nil {
		fmt.Println(err)
		return
	}

}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

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
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)

}

func nonceHandler(w http.ResponseWriter, r *http.Request) {

	value := r.Header.Values("jwkHash")

	if value == nil {
		fmt.Fprintf(w, "No jwkHash provided. Nonce request must contain the hash of the public key in header 'jwkHash'\n")
	} else {

		jwkHash := value[0]

		if jwkHash != "" {
			nonce := dpopjwt.GenerateNonce(24)
			nonces[jwkHash] = nonce
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("DPoP-Nonce", nonce)
			w.WriteHeader(http.StatusOK)
		}

	}

}
