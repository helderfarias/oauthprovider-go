package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/helderfarias/oauthprovider-go/model"
)

type TokenConverterDefault struct {
	ExpiryTimeInSecondsForAccessToken  int
	ExpiryTimeInSecondsForRefreshToken int
}

func (o *TokenConverterDefault) AccessToken(client *model.Client, scopes []string) string {
	return o.generateValue()
}

func (o *TokenConverterDefault) RefreshToken(client *model.Client, scopes []string) string {
	return o.generateValue()
}

func (o *TokenConverterDefault) CreateExpireTimeForAccessToken() time.Time {
	return o.calculateExpiryTime(o.ExpiryTimeInSecondsForAccessToken)
}

func (o *TokenConverterDefault) CreateExpireTimeForRefreshToken() time.Time {
	return o.calculateExpiryTime(o.ExpiryTimeInSecondsForRefreshToken)
}

func (o *TokenConverterDefault) generateValue() string {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}

func (o *TokenConverterDefault) calculateExpiryTime(daysInSeconds int) time.Time {
	expiresAt := time.Now()
	expiresAt = expiresAt.Add(time.Duration(daysInSeconds) * time.Second)
	return expiresAt.UTC()
}
