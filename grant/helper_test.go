package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"time"
)

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

func (f *FakeServer) CreateResponse(accessToken *model.AccessToken, refreshToken *model.RefreshToken) encode.Message {
	return &encode.OAuthMessage{AccessToken: "token00", TokenType: "Bearer", ExpiresIn: 3600}
}

func (f *FakeServer) IssuerAccessToken() string {
	return ""
}

func (f *FakeServer) IssuerExpireTimeForAccessToken() time.Time {
	return time.Time{}
}

func (f *FakeServer) IssuerExpireTimeForRefreshToken() time.Time {
	return time.Time{}
}

func (f *FakeServer) StoreAccessToken(accessToken *model.AccessToken) error { return nil }

func (f *FakeServer) StoreRefreshToken(refreshToken *model.RefreshToken) error { return nil }

func (f *FakeServer) HasGrantType(identified string) bool { return false }

func (f *FakeServer) RevokeToken(request http.Request) error { return nil }

func (f *FakeServer) FindRefreshTokenById(refreshToken string) *model.RefreshToken { return nil }

func (f *FakeServer) DeleteTokens(refreshToken *model.RefreshToken, accessToken *model.AccessToken) error {
	return nil
}
