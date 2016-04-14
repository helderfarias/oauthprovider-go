package server

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/storage/memory"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

type OAuthRequestFake struct {
	param     string
	paramsUri map[string]string
}

type OAuthResponseFake struct {
	param string
}

type GrantTypeFake struct {
	server servertype.Authorizable
}

type MessageFake struct {
}

func (o *OAuthResponseFake) RedirectUri(uri string) {
}

func (o *OAuthRequestFake) GetParam(key string) string {
	return o.param
}

func (o *OAuthRequestFake) GetAuthorizationCode() string {
	return o.param
}

func (o *OAuthRequestFake) GetParamUri(key string) string {
	return o.paramsUri[key]
}

func (o *OAuthRequestFake) GetScopes() []string {
	return []string{}
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

func (o *GrantTypeFake) HandleResponse(request http.Request) (encode.Message, error) {
	return &MessageFake{}, nil
}

func (g *GrantTypeFake) SetServer(origin servertype.Authorizable) {
	g.server = origin
}

func (g *GrantTypeFake) CheckScope(request http.Request, clientId string) ([]string, error) {
	return []string{}, nil
}

func (g *GrantTypeFake) isScopeRequired() bool {
	return false
}

func (g *GrantTypeFake) setScopeRequired(value bool) {
}

func (g *GrantTypeFake) getDefaultScope() string {
	return ""
}

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

func TestCreateAuthorizationCodeWithRedirectUriEmpty(t *testing.T) {
	server := NewAuthorizationServer()
	server.ClientStorage = &memory.MemoryClientStorage{}
	server.ScopeStorage = &memory.MemoryScopeStorage{}
	server.AuthzCodeStorage = &memory.MemoryAuthzCodeStorage{}
	server.TokenType = &token.BearerTokenType{}

	req := &OAuthRequestFake{param: "password", paramsUri: map[string]string{
		"client_id":     "client_id",
		"response_type": "code",
	}}

	res := &OAuthResponseFake{param: "password"}

	server.ClientStorage.Save(&model.Client{Name: "client_id", RedirectUri: "http://api.dev.one, http://api.dev.two"})

	code, err := server.HandlerAuthorize(req, res)

	assert.Nil(t, err)
	assert.NotEmpty(t, code)
	assert.Contains(t, code, "http://api.dev.one")
}

func TestCreateAuthorizationCodeWithRedirectUriNotEmpty(t *testing.T) {
	server := NewAuthorizationServer()
	server.ClientStorage = &memory.MemoryClientStorage{}
	server.ScopeStorage = &memory.MemoryScopeStorage{}
	server.AuthzCodeStorage = &memory.MemoryAuthzCodeStorage{}
	server.TokenType = &token.BearerTokenType{}

	req := &OAuthRequestFake{param: "password", paramsUri: map[string]string{
		"client_id":     "client_id",
		"response_type": "code",
		"redirect_uri":  "http://localhost:2000/api",
	}}

	res := &OAuthResponseFake{param: "password"}

	server.ClientStorage.Save(&model.Client{Name: "client_id", RedirectUri: "http://api.dev.one, http://api.dev.two"})

	code, err := server.HandlerAuthorize(req, res)

	assert.Nil(t, err)
	assert.NotEmpty(t, code)
	assert.Contains(t, code, "http://localhost:2000/api")
	assert.NotContains(t, code, "http://api.dev.one")
	assert.NotContains(t, code, "http://api.dev.two")
}
