package model

import "time"

type AuthzCode struct {
	ID          int64
	Code        string
	ClientId    string
	TokenExpiry int64
}

func (a *AuthzCode) Expired() bool {
	expiresAt := time.Unix(a.TokenExpiry, 0)
	if expiresAt.IsZero() {
		return false
	}

	now := time.Now().UTC()
	return expiresAt.After(now)
}
