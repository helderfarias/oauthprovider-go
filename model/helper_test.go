package model

import (
	"time"
)

func createDate(daysInSeconds int) time.Time {
	expiresAt := time.Now()
	days := time.Duration(daysInSeconds)
	expiresAt = expiresAt.Add(days * time.Second)
	return expiresAt
}
