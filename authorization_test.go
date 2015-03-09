package oauthprovider

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type OAuthRequestStub struct{}

func (o *OAuthRequestStub) GetParam(key string) string {
	return ""
}

type GrantTypeStub struct{}

func (g *GrantTypeStub) Identifier() string {
	return "password"
}

func TestNotNil(t *testing.T) {
	server := NewAuthorizationServer()
	req := &OAuthRequestStub{}

	ret, err := server.IssueAccessToken(req)

	assert.NotNil(t, server)
	assert.NotEmpty(t, ret)
	assert.Nil(t, err)
}

func TestShouldBeAddGrantType(t *testing.T) {
	server := NewAuthorizationServer()
	grantStub := &GrantTypeStub{}

	server.AddGrant(grantStub)

	assert.Equal(t, true, server.hasGrantType("password"))
}

func TestShouldBeAccessTokenRequest(t *testing.T) {
	server := NewAuthorizationServer()
	grantStub := &GrantTypeStub{}
	requestStub := &OAuthRequestStub{}

	grantStub

	server.AddGrant(grantStub)

	ret, err := server.IssueAccessToken(requestStub)

	assert.Nil(t, err)
	assert.Equal(t, "{accessToken: 12}", ret)
	// when(grantMock.identifier()).thenReturn("password");
	// when(requestMock.getParam("grant_type")).thenReturn("password");
	// when(grantMock.handleResponse(requestMock)).thenReturn(new OAuthMessageBearer());
	// grantMock.setServer(server);

	// server.addGrantType(grantMock);

	// String tokenResponse = server.issueAccessToken(requestMock);

	// assertThat(tokenResponse, is(notNullValue()));
}
