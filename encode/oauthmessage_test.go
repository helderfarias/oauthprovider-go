package encode

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncode(t *testing.T) {
	msg := &OAuthMessage{}
	msg.AccessToken = "token"
	msg.RefreshToken = "token"
	msg.ExpiresIn = 0
	msg.TokenType = "Bearer"

	assert.Equal(t, "{\"access_token\":\"token\",\"refresh_token\":\"token\",\"token_type\":\"Bearer\",\"expires_in\":0}", msg.Encode())
}
