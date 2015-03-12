package model

import (
	"github.com/helderfarias/oauthprovider-go/util"
	"time"
)

type RefreshToken struct {
	ID          int64
	Token       string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	User        *User
	Client      *Client
	AccessToken *AccessToken
}

func (a *RefreshToken) Expired() bool {
	if a.ExpiresAt.IsZero() {
		return false
	}

	return a.ExpiresAt.Add(-util.ACCESS_TOKEN_VALIDITY_SECONDS).Before(time.Now())
}

func (a *RefreshToken) Valid() bool {
	return a.Token != "" && !a.Expired()
}
