package server

import (
    "github.com/helderfarias/oauthprovider-go/http"
    "github.com/helderfarias/oauthprovider-go/model"
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

func (r *ResourceServer) GetAccessToken(request http.Request) (string, error) {
    authzHeader := request.GetHeader(util.AUTHORIZATION)

    if authzHeader == "" {
        return "", util.NewInvalidRequestError(util.OAUTH_ACCESS_TOKEN)
    }

    token := r.TokenType.GetAccessTokenInHeader(request)
    if token == "" {
        return "", util.NewAccessDeniedError()
    }

    return token, nil
}

func (r *ResourceServer) ValidateRequest(request http.Request) (*model.AccessToken, error) {
    authzHeader := request.GetHeader(util.AUTHORIZATION)

    if authzHeader == "" {
        return nil, util.NewInvalidRequestError(util.OAUTH_ACCESS_TOKEN)
    }

    token := r.TokenType.GetAccessTokenInHeader(request)
    if token == "" {
        return nil, util.NewAccessDeniedError()
    }

    accessToken := r.AccessTokenStorage.FindById(token)
    if accessToken == nil {
        return nil, util.NewAccessDeniedError()
    }

    if !accessToken.Valid() {
        return nil, util.NewAccessDeniedError()
    }

    return accessToken, nil
}
