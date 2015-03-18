package server

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/grant"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/storage"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
	"log"
	"time"
)

//Authorization Server for OAuth2
type AuthorizationServer struct {
	grants              map[string]grant.GrantType
	TokenType           token.TokenType
	ClientStorage       storage.ClientStorage
	AccessTokenStorage  storage.AccessTokenStorage
	RefreshTokenStorage storage.RefreshTokenStorage
	issuer              *util.OAuthIssuer
}

func NewAuthorizationServer() *AuthorizationServer {
	return &AuthorizationServer{
		grants: make(map[string]grant.GrantType),
		issuer: &util.OAuthIssuer{},
	}
}

func (a *AuthorizationServer) HasGrantType(identified string) bool {
	return a.grants[identified].Identifier() != ""
}

func (a *AuthorizationServer) AddGrant(grantType grant.GrantType) {
	grantType.SetServer(a)
	a.grants[grantType.Identifier()] = grantType
}

func (a *AuthorizationServer) CreateResponse(accessToken *model.AccessToken, refreshToken *model.RefreshToken) encode.Message {
	return a.TokenType.CreateResponse(accessToken, refreshToken)
}

func (a *AuthorizationServer) FindByCredencials(clientId, clientSecret string) *model.Client {
	return a.ClientStorage.FindByCredencials(clientId, clientSecret)
}

func (a *AuthorizationServer) FindRefreshTokenById(refreshToken string) *model.RefreshToken {
	return a.RefreshTokenStorage.FindById(refreshToken)
}

func (a *AuthorizationServer) IssuerAccessToken() string {
	return a.issuer.AccessToken()
}

func (a *AuthorizationServer) IssuerExpireTimeForAccessToken() time.Time {
	return a.issuer.CreateExpireTimeForAccessToken()
}

func (a *AuthorizationServer) IssuerExpireTimeForRefreshToken() time.Time {
	return a.issuer.CreateExpireTimeForRefreshToken()
}

func (a *AuthorizationServer) StoreAccessToken(token *model.AccessToken) {
	a.AccessTokenStorage.Save(token)
}

func (a *AuthorizationServer) StoreRefreshToken(token *model.RefreshToken) {
	a.RefreshTokenStorage.Save(token)
}

func (a *AuthorizationServer) DeleteTokens(refreshToken *model.RefreshToken, accessToken *model.AccessToken) {
	a.RefreshTokenStorage.Delete(refreshToken)
	a.AccessTokenStorage.Delete(accessToken)
}

func (a *AuthorizationServer) IssueAccessToken(request http.Request) (string, error) {
	grantType := request.GetParam(util.OAUTH_GRANT_TYPE)

	if grantType == "" {
		return "", util.NewInvalidRequestError(grantType)
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

	return message.Encode(), nil
}

func (a *AuthorizationServer) RevokeToken(request http.Request) error {
	token := request.GetParam(util.OAUTH_REVOKE_TOKEN)
	if token != "" {
		return util.NewInvalidRequestError(util.OAUTH_REVOKE_TOKEN)
	}

	if request.GetRevokeToken() == "" {
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

	a.RefreshTokenStorage.DeleteByAccessToken(accessToken)
	a.AccessTokenStorage.Delete(accessToken)

	return nil
}
