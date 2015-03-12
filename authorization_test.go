package oauthprovider

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

type OAuthRequestFake struct {
	param string
}

type GrantTypeFake struct {
	server server.Authorizable
}

type MessageFake struct {
}

func (o *OAuthRequestFake) GetParam(key string) string {
	return o.param
}

func (o *OAuthRequestFake) GetHeader(authorization string) string {
	return ""
}

func (o *OAuthRequestFake) GetClientId() string {
	return ""
}

func (o *OAuthRequestFake) GetClientSecret() string {
	return ""
}

func (o *OAuthRequestFake) GetUserName() string {
	return ""
}

func (o *OAuthRequestFake) GetPassword() string {
	return ""
}

func (o *OAuthRequestFake) GetGrantType() string {
	return ""
}

func (o *OAuthRequestFake) GetRefreshToken() string {
	return ""
}

func (o *OAuthRequestFake) GetAuthorizationBasic() []string {
	return nil
}

func (o *OAuthRequestFake) GetRevokeToken() string {
	return ""
}

func (g *GrantTypeFake) Identifier() string {
	return "password"
}

func (m *MessageFake) Encode() string {
	return ""
}

func (o *GrantTypeFake) HandleResponse(request http.Request) encode.Message {
	return &MessageFake{}
}

func (g *GrantTypeFake) SetServer(origin server.Authorizable) {
	g.server = origin
}

func TestShouldBeAddGrantType(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}

	server.AddGrant(grant)

	assert.Equal(t, true, server.hasGrantType("password"))
	assert.NotNil(t, grant.server)
}

func TestErrorIfGrantTypeEmptyWhenGetAccessToken(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}
	req := &OAuthRequestFake{param: ""}

	server.AddGrant(grant)

	_, err := server.IssueAccessToken(req)

	assert.NotNil(t, err)
	assert.Equal(t, err.(*util.OAuthError).GrantType, "invalid_request")
}

func TestErrorIfGrantTypeUnknownWhenGetAccessToken(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}
	req := &OAuthRequestFake{param: "unknown"}

	server.AddGrant(grant)

	_, err := server.IssueAccessToken(req)

	assert.NotNil(t, err)
	assert.Equal(t, err.(*util.OAuthError).GrantType, "unsupported_grant_type")
}

func TestCreateTokenValid(t *testing.T) {
	server := NewAuthorizationServer()
	grant := &GrantTypeFake{}
	req := &OAuthRequestFake{param: "password"}

	server.AddGrant(grant)

	token, err := server.IssueAccessToken(req)

	assert.Nil(t, err)
	assert.NotEqual(t, token, "message")
}
