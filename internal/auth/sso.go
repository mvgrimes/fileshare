package auth

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidSSOToken = errors.New("invalid sso token")

type SSOClaims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

type SSOValidator struct {
	secret   []byte
	issuer   string
	audience string
}

func NewSSOValidator(secret, issuer, audience string) *SSOValidator {
	return &SSOValidator{secret: []byte(secret), issuer: issuer, audience: audience}
}

func (v *SSOValidator) Validate(tokenString string) (SSOClaims, error) {
	if len(v.secret) == 0 || strings.TrimSpace(v.issuer) == "" || strings.TrimSpace(v.audience) == "" {
		return SSOClaims{}, ErrInvalidSSOToken
	}
	if strings.TrimSpace(tokenString) == "" {
		return SSOClaims{}, ErrInvalidSSOToken
	}

	claims := SSOClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, ErrInvalidSSOToken
		}
		return v.secret, nil
	},
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)
	if err != nil || !token.Valid {
		return SSOClaims{}, ErrInvalidSSOToken
	}
	if claims.Subject == "" && claims.UserID == "" {
		return SSOClaims{}, ErrInvalidSSOToken
	}
	return claims, nil
}
