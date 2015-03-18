package oauthprovider

import (
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/storage/memory"
	"github.com/helderfarias/oauthprovider-go/token"
)

type OAuthServer struct {
}

func New() *OAuthServer {
	return &OAuthServer{}
}

func (o *OAuthServer) AuthorizationServer() *server.AuthorizationServer {
	newServer := server.NewAuthorizationServer()
	newServer.AccessTokenStorage = &memory.MemoryAccessTokenStorage{}
	newServer.RefreshTokenStorage = &memory.MemoryRefreshTokenStorage{}
	newServer.ClientStorage = &memory.MemoryClientStorage{}
	newServer.TokenType = &token.BearerTokenType{}
	return newServer
}

func (o *OAuthServer) ResourceServer() *server.ResourceServer {
	return server.NewResourceServer()
}
