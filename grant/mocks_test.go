package grant

import (
	"time"

	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
)

type StubOAuthRequest struct {
	param map[string]string
	authz []string
}

type StubOAuthResponse struct {
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

func NewResponse() *StubOAuthResponse {
	return &StubOAuthResponse{param: make(map[string]string), authz: make([]string, 0)}
}

func NewServer() *FakeServer {
	return &FakeServer{credencials: &model.Client{}}
}

func (o *StubOAuthResponse) RedirectUri(uri string) {
}

func (o *StubOAuthRequest) GetParam(key string) string {
	return o.param[key]
}

func (o *StubOAuthRequest) GetParamUri(key string) string {
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

func (s *StubOAuthRequest) GetAuthorizationCode() string {
	return ""
}

func (o *StubOAuthRequest) GetRevokeToken() string {
	return ""
}

func (o *StubOAuthRequest) GetScopes() []string {
	return []string{}
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

func (f *FakeServer) CreateToken(*model.Client, []string) string {
	return ""
}

func (f *FakeServer) CreateRefreshToken(client *model.Client, copes []string) string {
	return ""
}

func (f *FakeServer) IssuerExpireTimeForAccessToken() time.Time {
	return time.Time{}
}

func (f *FakeServer) IssuerExpireTimeForRefreshToken() time.Time {
	return time.Time{}
}

func (f *FakeServer) FindAuthzCode(code, clientId string) (*model.AuthzCode, error) {
	return nil, nil
}

func (f *FakeServer) StoreAccessToken(accessToken *model.AccessToken) error { return nil }

func (f *FakeServer) StoreRefreshToken(refreshToken *model.RefreshToken) error { return nil }

func (f *FakeServer) HasGrantType(identified string) bool { return false }

func (f *FakeServer) HandlerRevokeToken(request http.Request, response http.Response) error {
	return nil
}

func (f *FakeServer) FindRefreshTokenById(refreshToken string) *model.RefreshToken { return nil }

func (f *FakeServer) DeleteTokens(refreshToken *model.RefreshToken, accessToken *model.AccessToken) error {
	return nil
}

func (a *FakeServer) FindScope(scope, clientId string) (*model.Scope, error) {
	return nil, nil
}

func (a *FakeServer) IsScopeRequired() bool {
	return false
}

func (f *FakeServer) FindClientById(clientId string) *model.Client {
	return nil
}

func (a *FakeServer) SetScopeRequired(value bool) {
}

func (a *FakeServer) GetDefaultScope() string {
	return ""
}

func (a *FakeServer) CheckScope(request http.Request, clientId string) ([]string, error) {
	return []string{}, nil
}

func (f *FakeServer) HandlerAccessToken(rrequest http.Request, response http.Response) (string, error) {
	return "", nil
}

func (f *FakeServer) HandlerAuthorize(request http.Request, response http.Response) (string, error) {
	return "", nil
}

func (f *FakeServer) StoreAuthzCode(code *model.AuthzCode) error {
	return nil
}
