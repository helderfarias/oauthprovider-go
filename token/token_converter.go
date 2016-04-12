package token

import (
	"time"
)

const (
	REFRESH_TOKEN_VALIDITY_SECONDS = (60 * 60 * 24 * 30)
	ACCESS_TOKEN_VALIDITY_SECONDS  = (60 * 60 * 24 * 7)
)

type TokenConverter interface {
	AccessToken() string
	RefreshToken() string
	CreateExpireTimeForAccessToken() time.Time
	CreateExpireTimeForRefreshToken() time.Time
}
