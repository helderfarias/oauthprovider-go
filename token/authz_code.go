package token

import (
	"crypto/rand"
	"encoding/hex"
)

type AuthorizeToken interface {
	GenerateCode() (string, error)
}

type AuthorizeTokenGenerator struct {
}

func (a *AuthorizeTokenGenerator) GenerateCode() (string, error) {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
