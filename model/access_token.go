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

    utcNow := time.Now()
    utcNow = time.Date(utcNow.Year(), utcNow.Month(), utcNow.Day(), utcNow.Hour(), utcNow.Minute(), utcNow.Second(), utcNow.Nanosecond(), time.UTC)
    return utcNow.After(a.ExpiresAt)
}

func (a *AccessToken) Valid() bool {
    return a.Token != "" && !a.Expired()
}
