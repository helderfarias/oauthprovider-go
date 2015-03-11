package http

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestShouldBeEmptyWhenHeaderIsEmptyDecodeHeader(t *testing.T) {
	oauthreq := &OAuthRequest{}

	assert.Nil(t, oauthreq.decodeHeader(""))
}

func TestShouldBeEmptyWhenSplitIsEmptyDecodeHeader(t *testing.T) {
	oauthreq := &OAuthRequest{}

	assert.Nil(t, oauthreq.decodeHeader("  "))
}

func TestShouldBeEmptyWhenNotAuthzBasicDecodeHeader(t *testing.T) {
	oauthreq := &OAuthRequest{}

	assert.Nil(t, oauthreq.decodeHeader("bearer 123"))
}

func TestDecodeHeaderValid(t *testing.T) {
	oauthreq := &OAuthRequest{}

	ret := oauthreq.decodeHeader("basic dXNlcjp1c2VyMDA=")

	assert.NotNil(t, ret)
	assert.Equal(t, ret, []string{"user", "user00"})
}
