package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
