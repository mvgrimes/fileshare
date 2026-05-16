package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileVerifier struct {
	httpClient *http.Client
	verifyURL  string
	siteKey    string
	secretKey  string
}

func newTurnstileVerifier(siteKey, secretKey string) *turnstileVerifier {
	return &turnstileVerifier{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		verifyURL:  turnstileVerifyURL,
		siteKey:    strings.TrimSpace(siteKey),
		secretKey:  strings.TrimSpace(secretKey),
	}
}

func (v *turnstileVerifier) enabled() bool {
	return v != nil && v.siteKey != "" && v.secretKey != ""
}

func (v *turnstileVerifier) verify(c echo.Context) bool {
	if !v.enabled() {
		return true
	}
	responseToken := strings.TrimSpace(c.FormValue("cf-turnstile-response"))
	if responseToken == "" {
		return false
	}
	payload := url.Values{}
	payload.Set("secret", v.secretKey)
	payload.Set("response", responseToken)
	payload.Set("remoteip", c.RealIP())

	resp, err := v.httpClient.PostForm(v.verifyURL, payload)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	var verifyResp struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return false
	}
	return verifyResp.Success
}
