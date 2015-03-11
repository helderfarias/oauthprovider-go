package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type FakeOAuthRequest struct {
	param string
}

type FakeMessage struct {
}

type FakeCredentialsCallback struct {
}

type FakeServer struct {
}

func (o *FakeOAuthRequest) GetParam(key string) string {
	return ""
}

func (o *FakeOAuthRequest) GetHeader(authorization string) string {
	return ""
}

func (o *FakeOAuthRequest) GetClientId() string {
	return ""
}

func (o *FakeOAuthRequest) GetClientSecret() string {
	return ""
}

func (o *FakeOAuthRequest) GetUserName() string {
	return ""
}

func (o *FakeOAuthRequest) GetPassword() string {
	return ""
}

func (o *FakeOAuthRequest) GetGrantType() string {
	return ""
}

func (o *FakeOAuthRequest) GetRefreshToken() string {
	return ""
}

func (o *FakeOAuthRequest) GetAuthorizationBasic() []string {
	return nil
}

func (o *FakeOAuthRequest) GetRevokeToken() string {
	return ""
}

func (v *FakeCredentialsCallback) Find(userName, password string) *model.User {
	return nil
}

func (f *FakeServer) FindByCredencials(clientId, clientSecret string) *model.Client {
	return &model.Client{}
}

func (f *FakeServer) CreateResponse(accessToken *model.AccessToken) encode.Message {
	return &encode.OAuthMessage{AccessToken: "token00", TokenType: "Bearer", ExpiresIn: 3600}
}

func (f *FakeServer) IssuerAccessToken() string {
	return ""
}

func (f *FakeServer) IssuerExpireTimeForAccessToken() time.Time {
	return time.Time{}
}

func (f *FakeServer) StoreAccessToken(accessToken *model.AccessToken) {

}

func TestCreate(t *testing.T) {
	grant := &PasswordGrant{}

	assert.NotNil(t, grant)
}

func TestShouldBeCreateMessageForOnlyAccessToken(t *testing.T) {
	grant := &PasswordGrant{}
	grant.callback = &FakeCredentialsCallback{}
	grant.server = &FakeServer{}
	req := &FakeOAuthRequest{param: ""}

	message := grant.HandleResponse(req)

	assert.NotNil(t, message)
	assert.Equal(t, message.Encode(), "{\"access_token\":\"token00\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
}
