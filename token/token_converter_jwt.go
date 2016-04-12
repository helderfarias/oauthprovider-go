package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type TokenConverterJwt struct {
	ExpiryTimeInSecondsForAccessToken  int
	ExpiryTimeInSecondsForRefreshToken int
}

func (o *TokenConverterJwt) AccessToken() string {
	return o.generateValue()
}

func (o *TokenConverterJwt) RefreshToken() string {
	return o.generateValue()
}

func (o *TokenConverterJwt) CreateExpireTimeForAccessToken() time.Time {
	return o.calculateExpiryTime(o.ExpiryTimeInSecondsForAccessToken)
}

func (o *TokenConverterJwt) CreateExpireTimeForRefreshToken() time.Time {
	return o.calculateExpiryTime(o.ExpiryTimeInSecondsForRefreshToken)
}

func (o *TokenConverterJwt) generateValue() string {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}

func (o *TokenConverterJwt) calculateExpiryTime(daysInSeconds int) time.Time {
	expiresAt := time.Now()
	expiresAt = expiresAt.Add(time.Duration(daysInSeconds) * time.Second)
	return expiresAt
}
