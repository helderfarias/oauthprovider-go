package model

import (
	"time"
)

type AccessToken struct {
	ID        float64
	Token     string
	ExpiresAt *time.Time
	CreatedAt *time.Time
	Client    *Client
	User      *User
}
