package model

import (
	"time"
)

type RefreshToken struct {
	ID          float64
	Token       string
	ExpiresAt   *time.Time
	CreatedAt   *time.Time
	user        *User
	client      *Client
	accessToken *AccessToken
}
