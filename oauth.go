package oauthprovider

import (
	"github.com/helderfarias/oauthprovider-go/authorization"
	"github.com/helderfarias/oauthprovider-go/server/core"
	"github.com/helderfarias/oauthprovider-go/storage/memory"
	"github.com/helderfarias/oauthprovider-go/token"
)

type OAuthServer struct {
}

func New() *OAuthServer {
	return &OAuthServer{}
}

func (o *OAuthServer) AuthorizationServer() *core.AuthorizationServer {
	newServer := core.NewAuthorizationServer()
	newServer.AddAuthzCode(authorization.NewAuthorizationCode())
	newServer.AddAuthzCode(authorization.NewAuthorizationToken())
	newServer.AccessTokenStorage = &memory.MemoryAccessTokenStorage{}
	newServer.RefreshTokenStorage = &memory.MemoryRefreshTokenStorage{}
	newServer.ClientStorage = &memory.MemoryClientStorage{}
	newServer.ScopeStorage = &memory.MemoryScopeStorage{}
	newServer.AuthzCodeStorage = &memory.MemoryAuthzCodeStorage{}
	newServer.TokenType = &token.BearerTokenType{}
	return newServer
}

func (o *OAuthServer) ResourceServer() *core.ResourceServer {
	newServer := core.NewResourceServer()
	newServer.AccessTokenStorage = &memory.MemoryAccessTokenStorage{}
	newServer.TokenType = &token.BearerTokenType{}
	return newServer
}
