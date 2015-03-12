package oauthprovider

import (
	"github.com/helderfarias/oauthprovider-go/server"
)

type OAuthServer struct {
}

func New() *OAuthServer {
	return &OAuthServer{}
}

func (o *OAuthServer) AuthorizationServer() *server.AuthorizationServer {
	return server.NewAuthorizationServer()
}

func (o *OAuthServer) ResourceServer() *server.ResourceServer {
	return server.NewResourceServer()
}
