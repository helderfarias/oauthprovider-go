package grant

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type OAuthRequestFake struct {
	param string
}

type MessageFake struct {
}

func (o *OAuthRequestFake) GetParam(key string) string {
	return ""
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

func TestCreate(t *testing.T) {
	grant := &PasswordGrant{}

	assert.NotNil(t, grant)
}

func TestShouldBeCreateMessageForOnlyAccessToken(t *testing.T) {
	grant := &PasswordGrant{}
	req := &OAuthRequestFake{param: ""}

	message := grant.HandleResponse(req)

	assert.NotNil(t, message)
	assert.Equal(t, message.Encode(), "{\"access_token\":\"token00\", \"token_type\":\"Bearer\", \"expires_in\":3600}")
}
