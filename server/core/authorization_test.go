package core

import (
	"testing"

	"github.com/helderfarias/oauthprovider-go/util"
	"github.com/stretchr/testify/assert"
)

func TestShouldBeAddGrantType(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}

	server.AddGrant(grant)

	assert.Equal(t, true, server.HasGrantType("password"))
	assert.NotNil(t, grant.server)
}

func TestErrorIfGrantTypeEmptyWhenGetAccessToken(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}
	req := &OAuthRequestFake{param: ""}
	res := &OAuthResponseFake{param: ""}

	server.AddGrant(grant)

	_, err := server.HandlerAccessToken(req, res)

	assert.NotNil(t, err)
	assert.Equal(t, err.(*util.OAuthError).GrantType, "invalid_request")
}

func TestErrorIfGrantTypeUnknownWhenGetAccessToken(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}
	req := &OAuthRequestFake{param: "unknown"}
	res := &OAuthResponseFake{param: ""}

	server.AddGrant(grant)

	_, err := server.HandlerAccessToken(req, res)

	assert.NotNil(t, err)
	assert.Equal(t, err.(*util.OAuthError).GrantType, "unsupported_grant_type")
}

func TestCreateTokenValid(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}
	req := &OAuthRequestFake{param: "password"}
	res := &OAuthResponseFake{param: ""}

	server.AddGrant(grant)

	token, err := server.HandlerAccessToken(req, res)

	assert.Nil(t, err)
	assert.NotEqual(t, token, "message")
}
