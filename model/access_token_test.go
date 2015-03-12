package model

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateAccessToken(t *testing.T) {
	accessToken := &AccessToken{}
	accessToken.ExpiresAt = createDate(2592000)

	assert.NotEqual(t, 0, accessToken.ExpiresAtInMilliseconds())
}
