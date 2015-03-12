package model

import (
	"github.com/helderfarias/oauthprovider-go/util"
	"time"
)

type AccessToken struct {
	ID        int64
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
	Client    *Client
	User      *User
}

func (a *AccessToken) ExpiresAtInMilliseconds() int64 {
	return a.ExpiresAt.UnixNano() / int64(time.Millisecond)
}

func (a *AccessToken) Expired() bool {
	if a.ExpiresAt.IsZero() {
		return false
	}
	return a.ExpiresAt.Add(-util.ACCESS_TOKEN_VALIDITY_SECONDS).Before(time.Now())
}

func (a *AccessToken) Valid() bool {
	return a.Token != "" && !a.Expired()
}
