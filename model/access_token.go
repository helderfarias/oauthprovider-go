package model

import (
	"time"
)

type AccessToken struct {
	ID        float64
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
	Client    *Client
	User      *User
}

func (a *AccessToken) ExpiresAtInMilliseconds() int64 {
	return a.ExpiresAt.UnixNano() / int64(time.Millisecond)
}
