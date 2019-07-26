package token

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreate(t *testing.T) {
	converter := &TokenConverterDefault{
		ExpiryTimeInSecondsForAccessToken:  ACCESS_TOKEN_VALIDITY_SECONDS,
		ExpiryTimeInSecondsForRefreshToken: REFRESH_TOKEN_VALIDITY_SECONDS,
	}

	assert.NotNil(t, converter)
}

func TestGenerateValue(t *testing.T) {
	converter := &TokenConverterDefault{
		ExpiryTimeInSecondsForAccessToken:  ACCESS_TOKEN_VALIDITY_SECONDS,
		ExpiryTimeInSecondsForRefreshToken: REFRESH_TOKEN_VALIDITY_SECONDS,
	}

	access := converter.AccessToken(nil, nil)
	refresh := converter.RefreshToken(nil, nil)

	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
	assert.Len(t, access, 32)
	assert.Len(t, refresh, 32)
}

func TestCreateExpireTimeForAccessToken(t *testing.T) {
	converter := &TokenConverterDefault{
		ExpiryTimeInSecondsForAccessToken:  ACCESS_TOKEN_VALIDITY_SECONDS,
		ExpiryTimeInSecondsForRefreshToken: REFRESH_TOKEN_VALIDITY_SECONDS,
	}

	expireTime := converter.CreateExpireTimeForAccessToken()

	assert.NotNil(t, expireTime)
	assert.Equal(t, fmt.Sprintf("%0.f", math.Trunc(expireTime.Sub(time.Now()).Hours())), "167")
}

func TestCreateExpireTimeForRefreshToken(t *testing.T) {
	converter := &TokenConverterDefault{
		ExpiryTimeInSecondsForAccessToken:  ACCESS_TOKEN_VALIDITY_SECONDS,
		ExpiryTimeInSecondsForRefreshToken: REFRESH_TOKEN_VALIDITY_SECONDS,
	}

	expireTime := converter.CreateExpireTimeForRefreshToken()

	assert.NotNil(t, expireTime)
	assert.Equal(t, fmt.Sprintf("%0.f", math.Trunc(expireTime.Sub(time.Now()).Hours())), "719")
}
