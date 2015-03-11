package oauthprovider

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

type AuthorizationServer struct {
	grants        map[string]grant.GrantType
	tokenType     token.TokenType
	clientStorage storage.ClientStorage
}

func NewAuthorizationServer() *AuthorizationServer {
	return &AuthorizationServer{
		grants: make(map[string]grant.GrantType),
	}
}

func (a *AuthorizationServer) hasGrantType(identified string) bool {
	return a.grants[identified].Identifier() != ""
}

func (a *AuthorizationServer) AddGrant(grantType grant.GrantType) {
	a.grants[grantType.Identifier()] = grantType
}

func (a *AuthorizationServer) CreateResponse(accessToken *model.AccessToken) encode.Message {
	return a.tokenType.CreateResponse(accessToken)
}

func (a *AuthorizationServer) FindByCredencials(clientId, clientSecret string) *model.Client {
	return a.clientStorage.FindByCredencials(clientId, clientSecret)
}

func (a *AuthorizationServer) IssuerAccessToken() string {
	return ""
}

func (a *AuthorizationServer) IssuerExpireTimeForAccessToken() *time.Time {
	return nil
}

func (a *AuthorizationServer) IssueAccessToken(request http.Request) (string, error) {
	grantType := request.GetParam(util.OAUTH_GRANT_TYPE)

	if grantType == "" {
		return "", util.NewInvalidRequestError(grantType)
	}

	if _, ok := a.grants[grantType]; !ok {
		return "", util.NewUnSupportedGrantTypeError(grantType)
	}

	message := a.grants[grantType].HandleResponse(request)

	if message == nil {
		log.Fatalln("HandleResponse not intialize")
	}

	return message.Encode(), nil
}
