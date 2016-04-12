package model

import (
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

func (a *RefreshToken) Expired(seconds int) bool {
	if a.ExpiresAt.IsZero() {
		return false
	}

	return a.ExpiresAt.Add(-1 * time.Duration(seconds)).Before(time.Now())
}

func (a *RefreshToken) Valid(seconds int) bool {
	return a.Token != "" && !a.Expired(seconds)
}
