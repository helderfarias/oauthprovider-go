package model

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateRefreshToken(t *testing.T) {
	token := &RefreshToken{}
	token.ExpiresAt = createDate(2592000)

	assert.Equal(t, false, token.Expired(0))
}
