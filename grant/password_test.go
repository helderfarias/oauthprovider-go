package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	grant := &PasswordGrant{}

	assert.NotNil(t, grant)
}

func TestShouldBeCreateMessageForOnlyAccessToken(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	callback := &FakeCredentialsCallback{}
	grant := &PasswordGrant{}
	grant.callback = callback
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = "user"
	req.param["password"] = "user00"
	server.credencials = &model.Client{Name: "client", Secret: "secret"}
	callback.user = &model.User{}

	message, _ := grant.HandleResponse(req)

	assert.NotNil(t, message)
	assert.Equal(t, message.Encode(), "{\"access_token\":\"token00\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
}

func TestErrorIfClientIdNullWhenHandleReponse(t *testing.T) {
	grant := &PasswordGrant{}
	req := NewRequest()

	req.param["clientId"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfClientSecretNullWhenHandleReponse(t *testing.T) {
	grant := &PasswordGrant{}
	req := NewRequest()

	req.param["clientId"] = "client"
	req.param["clientSecret"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfClientNotExistsWhenHandleReponse(t *testing.T) {
	grant := &PasswordGrant{}
	grant.callback = &FakeCredentialsCallback{}
	grant.server = &FakeServer{}
	req := NewRequest()

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = nil

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfUserNameNullWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	callback := &FakeCredentialsCallback{}
	grant := &PasswordGrant{}
	grant.callback = callback
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfPasswordNullWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	callback := &FakeCredentialsCallback{}
	grant := &PasswordGrant{}
	grant.callback = callback
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = "username"
	req.param["password"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfCallBackNullWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	callback := &FakeCredentialsCallback{}
	grant := &PasswordGrant{}
	grant.callback = callback
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = "username"
	req.param["password"] = "password"
	server.credencials = &model.Client{Name: "client", Secret: "secret"}
	callback.user = nil

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfInvalidAuthorizationHashWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	callback := &FakeCredentialsCallback{}
	grant := &PasswordGrant{}
	grant.callback = callback
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", ""}

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

type StubOAuthRequest struct {
	param map[string]string
	authz []string
}

type FakeMessage struct {
}

type FakeCredentialsCallback struct {
	user *model.User
}

type FakeServer struct {
	credencials *model.Client
}

func NewRequest() *StubOAuthRequest {
	return &StubOAuthRequest{param: make(map[string]string), authz: make([]string, 0)}
}

func NewServer() *FakeServer {
	return &FakeServer{credencials: &model.Client{}}
}

func (o *StubOAuthRequest) GetParam(key string) string {
	return o.param[key]
}

func (o *StubOAuthRequest) GetHeader(authorization string) string {
	return ""
}

func (o *StubOAuthRequest) GetClientId() string {
	return o.GetParam("clientId")
}

func (o *StubOAuthRequest) GetClientSecret() string {
	return o.GetParam("clientSecret")
}

func (o *StubOAuthRequest) GetUserName() string {
	return o.GetParam("username")
}

func (o *StubOAuthRequest) GetPassword() string {
	return o.GetParam("password")
}

func (o *StubOAuthRequest) GetGrantType() string {
	return ""
}

func (o *StubOAuthRequest) GetRefreshToken() string {
	return ""
}

func (o *StubOAuthRequest) GetAuthorizationBasic() []string {
	return o.authz
}

func (o *StubOAuthRequest) GetRevokeToken() string {
	return ""
}

func (v *FakeCredentialsCallback) Find(userName, password string) *model.User {
	return v.user
}

func (f *FakeServer) FindByCredencials(clientId, clientSecret string) *model.Client {
	return f.credencials
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

func (f *FakeServer) StoreAccessToken(accessToken *model.AccessToken) {}
