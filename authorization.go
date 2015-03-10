package oauthprovider

import (
	"github.com/helderfarias/oauthprovider-go/grant"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/util"
	"log"
)

type AuthorizationServer struct {
	grants map[string]grant.GrantType
}

func NewAuthorizationServer() *AuthorizationServer {
	return &AuthorizationServer{
		grants: make(map[string]grant.GrantType),
	}
}

func (this *AuthorizationServer) hasGrantType(identified string) bool {
	return this.grants[identified].Identifier() != ""
}

func (this *AuthorizationServer) AddGrant(grantType grant.GrantType) {
	this.grants[grantType.Identifier()] = grantType
}

func (this *AuthorizationServer) IssueAccessToken(request http.Request) (string, error) {
	grantType := request.GetParam(util.OAUTH_GRANT_TYPE)

	if grantType == "" {
		return "", util.NewInvalidRequestError(grantType)
	}

	if _, ok := this.grants[grantType]; !ok {
		return "", util.NewUnSupportedGrantTypeError(grantType)
	}

	message := this.grants[grantType].HandleResponse(request)

	if message == nil {
		log.Fatalln("HandleResponse not intialize")
	}

	return message.Encode(), nil
}
