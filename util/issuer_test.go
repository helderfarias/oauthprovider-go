package util

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	issuer := &OAuthIssuer{}

	assert.NotNil(t, issuer)
}

func TestGenerateValue(t *testing.T) {
	issuer := &OAuthIssuer{}

	access := issuer.AccessToken()
	refresh := issuer.RefreshToken()

	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
	assert.Len(t, access, 32)
	assert.Len(t, refresh, 32)
}

func TestCreateExpireTimeForAccessToken(t *testing.T) {
	issuer := &OAuthIssuer{}

	expireTime := issuer.CreateExpireTimeForAccessToken()

	assert.NotNil(t, expireTime)
	assert.Equal(t, math.Trunc(expireTime.Sub(time.Now()).Hours()), 167)
}

func TestCreateExpireTimeForRefreshToken(t *testing.T) {
	issuer := &OAuthIssuer{}

	expireTime := issuer.CreateExpireTimeForRefreshToken()

	assert.NotNil(t, expireTime)
	assert.Equal(t, math.Trunc(expireTime.Sub(time.Now()).Hours()), 719)
}
