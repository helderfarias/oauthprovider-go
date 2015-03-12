package util

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const (
	REFRESH_TOKEN_VALIDITY_SECONDS = 60 * 60 * 24 * 30
	ACCESS_TOKEN_VALIDITY_SECONDS  = 60 * 60 * 24 * 7
)

type OAuthIssuer struct {
}

func (o *OAuthIssuer) AccessToken() string {
	return o.generateValue()
}

func (o *OAuthIssuer) RefreshToken() string {
	return o.generateValue()
}

func (o *OAuthIssuer) CreateExpireTimeForAccessToken() time.Time {
	return o.calculateExpiryTime(ACCESS_TOKEN_VALIDITY_SECONDS)
}

func (o *OAuthIssuer) CreateExpireTimeForRefreshToken() time.Time {
	return o.calculateExpiryTime(REFRESH_TOKEN_VALIDITY_SECONDS)
}

func (o *OAuthIssuer) generateValue() string {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}

func (o *OAuthIssuer) calculateExpiryTime(daysInSeconds int) time.Time {
	expiresAt := time.Now()
	days := time.Duration(daysInSeconds)
	expiresAt = expiresAt.Add(days * time.Second)
	return expiresAt
}
