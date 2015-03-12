package util

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const (
	REFRESH_TOKEN_VALIDITY_SECONDS = (60 * 60 * 24 * 30) * time.Second
	ACCESS_TOKEN_VALIDITY_SECONDS  = (60 * 60 * 24 * 7) * time.Second
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

func (o *OAuthIssuer) calculateExpiryTime(daysInSeconds time.Duration) time.Time {
	expiresAt := time.Now()
	expiresAt = expiresAt.Add(daysInSeconds)
	return expiresAt
}
