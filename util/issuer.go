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

func (o *OAuthIssuer) CreateExpireTimeForAccessToken() *time.Time {
	return nil
}

func (o *OAuthIssuer) CreateExpireTimeForRefreshToken() *time.Time {
	return nil
}

func (o *OAuthIssuer) generateValue() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 	@Override
// 	public Date createExpireTimeForAccessToken() {
// 		return new Date(System.currentTimeMillis() + (ACCESS_TOKEN_VALIDITY_SECONDS * 1000L));
// 	}

// 	@Override
// 	public Date createExpireTimeForRefreshToken() {
// 		return new Date(System.currentTimeMillis() + (REFRESH_TOKEN_VALIDITY_SECONDS * 1000L));
// 	}
