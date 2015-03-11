package model

import (
	"time"
)

type Client struct {
	ID           float64
	Name         string
	Secret       string
	Status       int
	lastLockAt   time.Time
	lastUnlockAt time.Time
}
