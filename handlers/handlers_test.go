package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dpopjwt "github.com/thiagocamargodacosta/dpopjwt/v0"
)

func TestTokenHandler(t *testing.T) {

	t.Log("Assemble POST request to /token")

	req, err := http.NewRequest("POST", "/token", nil)

	if err != nil {
		t.Fatal(err)
	}

	t.Log("Set the required headers")

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", "")

	t.Log("Create response recorder")
	w := httptest.NewRecorder()

	t.Log("Send the request")

	tokenHandler(w, req)

	resp := w.Result()

	t.Log("Evaluate the response")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected response status: %v, Got: %v\n", http.StatusOK, resp.StatusCode)
	}

	content_type := resp.Header.Values("Content-Type")[0]

	if content_type != "application/json" {
		t.Error("Expected response to be of type application/json\n")
	}

	cache_control := resp.Header.Values("Cache-Control")[0]

	if cache_control != "no-store" {
		t.Error("Expected no-store string in Cache-Control header\n")
	}

	defer resp.Body.Close()

	t.Log("Read content of response body")

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)

	if err != nil {
		t.Error("Error reading response body:", err)
	}

	t.Log("Expect content of body to be unmarshalable")

	var contentJSON map[string]interface{}

	err = json.Unmarshal(buf.Bytes(), &contentJSON)

	if err != nil {
		t.Error("Error while unmarshaling response body")
	}

	t.Log("Expect response body to contain a 'token_type' key with value 'DPoP'")

	value, exists := contentJSON["token_type"]

	if !exists {
		t.Error("Response should contain 'token_type'")
	}

	if strings.ToLower(value.(string)) != "dpop" {
		t.Errorf("Value in token_type is not dpop. Got %s", value.(string))
	}
}

func TestNonceHandler(t *testing.T) {

	t.Log("Assemble POST request to /nonce")

	req, err := http.NewRequest("POST", "/nonce", nil)

	if err != nil {
		t.Fatal(err)
	}

	t.Log("Set required header value")

	req.Header.Set("jkt", "example-value")

	t.Log("Create response recorder")
	w := httptest.NewRecorder()

	t.Log("Send the request")
	nonceHandler(w, req)

	resp := w.Result()

	t.Log("Evaluate the response")
	nonce := resp.Header.Values("DPoP-Nonce")[0]
	cache_control := resp.Header["Cache-Control"][0]

	t.Log("Value in DPoP-Nonce header should be non-empty")
	if nonce == "" {
		t.Error("Expected non-empty string in DPoP-Nonce header\n")
	}

	t.Log("Value in DPoP-Nonce should be a valid nonce")
	if flag, _ := dpopjwt.CheckNonce(nonce); flag == false {
		t.Errorf("Received invalid nonce from %s", req.URL.Path)
	}

	t.Log("Value in Cache-Control should be no-store")
	if cache_control != "no-store" {
		t.Error("Expected no-store string in Cache-Control header\n")
	}

	t.Log("HTTP Status Code should be 201 (Created)")
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected response status: %v, Got: %v\n", http.StatusOK, resp.StatusCode)
	}
}
