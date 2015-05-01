package model

import (
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
    if a.ExpiresAt.IsZero() {
        return 0
    }

    return a.ExpiresAt.UnixNano() / int64(time.Millisecond)
}

func (a *AccessToken) Expired() bool {
    if a.ExpiresAt.IsZero() {
        return false
    }

    return time.Now().After(a.ExpiresAt)
}

func (a *AccessToken) Valid() bool {
    return a.Token != "" && !a.Expired()
}
