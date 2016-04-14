package server

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/grant"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/scope"
	"github.com/helderfarias/oauthprovider-go/storage"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
)

//Authorization Server for OAuth2
type AuthorizationServer struct {
	grants              map[string]grant.GrantType
	scopeRequired       bool
	defaultScope        string
	TokenType           token.TokenType
	ClientStorage       storage.ClientStorage
	AccessTokenStorage  storage.AccessTokenStorage
	RefreshTokenStorage storage.RefreshTokenStorage
	ScopeStorage        storage.ScopeStorage
	AuthzCodeStorage    storage.AuthzCodeStorage
	TokenConverter      token.TokenConverter
	AuthorizeToken      token.AuthorizeToken
}

func NewAuthorizationServer() *AuthorizationServer {
	return &AuthorizationServer{
		grants:         make(map[string]grant.GrantType),
		AuthorizeToken: &token.AuthorizeTokenGenerator{},
		TokenConverter: &token.TokenConverterDefault{
			ExpiryTimeInSecondsForAccessToken:  token.ACCESS_TOKEN_VALIDITY_SECONDS,
			ExpiryTimeInSecondsForRefreshToken: token.REFRESH_TOKEN_VALIDITY_SECONDS,
		},
	}
}

func (a *AuthorizationServer) FindScope(scope, clientId string) (*model.Scope, error) {
	return a.ScopeStorage.Find(scope, clientId)
}

func (a *AuthorizationServer) IsScopeRequired() bool {
	return a.scopeRequired
}

func (a *AuthorizationServer) SetScopeRequired(value bool) {
	a.scopeRequired = value
}

func (a *AuthorizationServer) GetDefaultScope() string {
	return a.defaultScope
}

func (a *AuthorizationServer) CheckScope(request http.Request, clientId string) ([]string, error) {
	validator := scope.ValidatorScope{Server: a}

	return validator.Execute(request, clientId)
}

func (a *AuthorizationServer) HasGrantType(identified string) bool {
	if a.grants[identified] == nil {
		return false
	}

	return a.grants[identified].Identifier() != ""
}

func (a *AuthorizationServer) AddGrant(grantType grant.GrantType) {
	grantType.SetServer(a)
	a.grants[grantType.Identifier()] = grantType
}

func (a *AuthorizationServer) CreateResponse(accessToken *model.AccessToken, refreshToken *model.RefreshToken) encode.Message {
	return a.TokenType.CreateResponse(accessToken, refreshToken)
}

func (a *AuthorizationServer) FindAuthzCode(code, clientId string) (*model.AuthzCode, error) {
	return a.AuthzCodeStorage.Find(code, clientId)
}

func (a *AuthorizationServer) FindClientById(clientId string) *model.Client {
	return a.ClientStorage.FindById(clientId)
}

func (a *AuthorizationServer) FindByCredencials(clientId, clientSecret string) *model.Client {
	return a.ClientStorage.FindByCredencials(clientId, clientSecret)
}

func (a *AuthorizationServer) FindRefreshTokenById(refreshToken string) *model.RefreshToken {
	return a.RefreshTokenStorage.FindById(refreshToken)
}

func (a *AuthorizationServer) CreateToken() string {
	return a.TokenConverter.AccessToken()
}

func (a *AuthorizationServer) IssuerExpireTimeForAccessToken() time.Time {
	return a.TokenConverter.CreateExpireTimeForAccessToken()
}

func (a *AuthorizationServer) IssuerExpireTimeForRefreshToken() time.Time {
	return a.TokenConverter.CreateExpireTimeForRefreshToken()
}

func (a *AuthorizationServer) StoreAccessToken(token *model.AccessToken) error {
	return a.AccessTokenStorage.Save(token)
}

func (a *AuthorizationServer) StoreRefreshToken(token *model.RefreshToken) error {
	return a.RefreshTokenStorage.Save(token)
}

func (a *AuthorizationServer) DeleteTokens(refreshToken *model.RefreshToken, accessToken *model.AccessToken) error {
	err := a.RefreshTokenStorage.Delete(refreshToken)
	if err != nil {
		return err
	}

	return a.AccessTokenStorage.Delete(accessToken)
}

//Issue authorize code
func (this *AuthorizationServer) HandlerAuthorize(request http.Request, response http.Response) (string, error) {
	reponseType := request.GetParamUri(util.OAUTH_RESPONSE_TYPE)
	if reponseType == "" {
		return "", util.NewInvalidRequestError(util.OAUTH_RESPONSE_TYPE)
	}

	clientId := request.GetParamUri(util.OAUTH_CLIENT_ID)
	if clientId == "" {
		return "", util.NewInvalidRequestError(util.OAUTH_CLIENT_ID)
	}

	redirectUri, err := url.QueryUnescape(request.GetParamUri(util.OAUTH_REDIRECT_URI))
	if err != nil {
		return "", util.NewInvalidRequestError(util.OAUTH_REDIRECT_URI)
	}

	client := this.FindClientById(clientId)
	if client == nil {
		return "", util.NewInvalidClientError()
	}

	if client.RedirectUri == "" {
		return "", util.NewUnauthorizedClientError()
	}

	if redirectUri == "" {
		redirectUri = this.getFirstUri(client.RedirectUri)
	}

	_, err = this.CheckScope(request, clientId)
	if err != nil {
		return "", util.NewInvalidScopeError()
	}

	authzCode, err := this.AuthorizeToken.GenerateCode()
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	err = this.AuthzCodeStorage.Save(&model.AuthzCode{Code: authzCode, ClientId: clientId})
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	responseUri := fmt.Sprintf("%s?code=%s", redirectUri, authzCode)

	response.RedirectUri(responseUri)

	return responseUri, nil
}

//Issue token
func (a *AuthorizationServer) HandlerAccessToken(request http.Request, response http.Response) (string, error) {
	grantType := request.GetParam(util.OAUTH_GRANT_TYPE)

	if grantType == "" {
		return "", util.NewInvalidRequestError(grantType)
	}

	if grantType == util.OAUTH_AUTHORIZATION_CODE {
		_, err := url.QueryUnescape(request.GetParamUri(util.OAUTH_REDIRECT_URI))
		if err != nil {
			return "", util.NewInvalidRequestError(util.OAUTH_REDIRECT_URI)
		}
	}

	if _, ok := a.grants[grantType]; !ok {
		return "", util.NewUnSupportedGrantTypeError(grantType)
	}

	message, err := a.grants[grantType].HandleResponse(request)
	if err != nil {
		return "", err
	}

	if message == nil {
		log.Panicln("Handler Response not initialize")
	}

	token := message.Encode()

	if grantType == util.OAUTH_AUTHORIZATION_CODE {
		uri := request.GetParamUri(util.OAUTH_REDIRECT_URI)
		response.RedirectUri(fmt.Sprintf("%s?token=%s", uri, token))
		return token, nil
	}

	return token, nil
}

//Revoke token
func (a *AuthorizationServer) HandlerRevokeToken(request http.Request, response http.Response) error {
	token := request.GetRevokeToken()
	if token == "" {
		return util.NewInvalidRequestError(util.OAUTH_REVOKE_TOKEN)
	}

	authz := request.GetAuthorizationBasic()
	if authz == nil || authz[0] == "" || authz[1] == "" {
		return util.NewBadCredentialsError()
	}

	client := a.ClientStorage.FindByCredencials(authz[0], authz[1])
	if client == nil {
		return util.NewInvalidClientError()
	}

	accessToken := a.AccessTokenStorage.FindById(token)
	if accessToken == nil {
		return util.NewInvalidAccessTokenError()
	}

	err := a.RefreshTokenStorage.DeleteByAccessToken(accessToken)
	if err != nil {
		return util.NewOAuthRuntimeError()
	}

	err = a.AccessTokenStorage.Delete(accessToken)
	if err != nil {
		return util.NewOAuthRuntimeError()
	}

	return nil
}

func (a *AuthorizationServer) getFirstUri(uriList string) string {
	if uriList == "" {
		return ""
	}

	firstUri := ""

	items := strings.Split(uriList, ",")
	if len(items) > 0 {
		firstUri = items[0]
	}

	if util.IsURL(firstUri) {
		return firstUri
	}

	return ""
}
