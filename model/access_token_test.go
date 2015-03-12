package model

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	accessToken := &AccessToken{}
	accessToken.ExpiresAt = createDate(2592000)

	assert.NotEqual(t, 0, accessToken.ExpiresAtInMilliseconds())
}

func createDate(daysInSeconds int) time.Time {
	expiresAt := time.Now()
	days := time.Duration(daysInSeconds)
	expiresAt = expiresAt.Add(days * time.Second)
	return expiresAt
}
