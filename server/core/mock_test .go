package core

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server"
)

type OAuthRequestFake struct {
	param     string
	paramsUri map[string]string
}

type OAuthResponseFake struct {
	param    string
	redirect string
}

type GrantTypeFake struct {
	server server.Authorizable
}

type MessageFake struct {
}

func (o *OAuthResponseFake) RedirectUri(uri string) {
	o.redirect = uri
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

func (m *MessageFake) Message() encode.OAuthMessage {
	return encode.OAuthMessage{}
}

func (o *GrantTypeFake) HandleResponse(request http.Request) (encode.Message, error) {
	return &MessageFake{}, nil
}

func (g *GrantTypeFake) SetServer(origin server.Authorizable) {
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

