package token

import (
	"time"

	"github.com/helderfarias/oauthprovider-go/model"
)

const (
	REFRESH_TOKEN_VALIDITY_SECONDS = (60 * 60 * 24 * 30)
	ACCESS_TOKEN_VALIDITY_SECONDS  = (60 * 60 * 24 * 7)
)

type TokenConverter interface {
	AccessToken(client *model.Client, scopes []string) string

	RefreshToken(client *model.Client, scopes []string) string

	CreateExpireTimeForAccessToken() time.Time

	CreateExpireTimeForRefreshToken() time.Time
}
