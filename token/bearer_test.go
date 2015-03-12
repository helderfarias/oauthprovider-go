package token

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

type OAuthRequestFake struct {
	header string
}

func (o *OAuthRequestFake) GetParam(key string) string {
	return ""
}

func (o *OAuthRequestFake) GetHeader(authorization string) string {
	return "bearer token10"
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

func TestCreate(t *testing.T) {
	tokenType := &BearerTokenType{}
	accessToken := &model.AccessToken{}

	message := tokenType.CreateResponse(accessToken)

	assert.NotNil(t, message)
}

func TestGetAccessTokenInHeader(t *testing.T) {
	tokenType := &BearerTokenType{}
	req := &OAuthRequestFake{}

	message := tokenType.GetAccessTokenInHeader(req)

	assert.NotNil(t, message)
	assert.NotEqual(t, "", message)
}
