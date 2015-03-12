package server

import (
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/storage"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
)

//Resource Server for OAuth2
type ResourceServer struct {
	TokenType          token.TokenType
	AccessTokenStorage storage.AccessTokenStorage
}

func NewResourceServer() *ResourceServer {
	return &ResourceServer{}
}

func (r *ResourceServer) ValidateRequest(request http.Request) error {
	authzHeader := request.GetHeader(util.AUTHORIZATION)

	if authzHeader == "" {
		return util.NewInvalidRequestError(util.OAUTH_ACCESS_TOKEN)
	}

	token := r.TokenType.GetAccessTokenInHeader(request)
	if token == "" {
		return util.NewAccessDeniedError()
	}

	accessToken := r.AccessTokenStorage.FindById(token)
	if accessToken == nil {
		return util.NewAccessDeniedError()
	}

	if accessToken.Expired() {
		return util.NewAccessDeniedError()
	}

	return nil
}
