package model

import (
	"time"
)

type Client struct {
	ID           int64
	Name         string
	Secret       string
	Status       int
	RedirectUri  string
	lastLockAt   time.Time
	lastUnlockAt time.Time
}
