package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSSOValidatorValidateValidToken(t *testing.T) {
	v := NewSSOValidator("secret", "issuer-1", "aud-1")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, SSOClaims{
		UserID: "u-1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer-1",
			Audience:  jwt.ClaimStrings{"aud-1"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Subject:   "sub-1",
		},
	})
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("SignedString() error: %v", err)
	}

	claims, err := v.Validate(signed)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if claims.UserID != "u-1" {
		t.Fatalf("claims.UserID = %q, want %q", claims.UserID, "u-1")
	}
}

func TestSSOValidatorValidateInvalidToken(t *testing.T) {
	v := NewSSOValidator("secret", "issuer-1", "aud-1")
	if _, err := v.Validate("invalid"); err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}
