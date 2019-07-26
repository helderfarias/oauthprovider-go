package authorization

import (
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server"
)

type AuthorizeType interface {
	Identifier() string

	SetServer(server server.Authorizable)

	HandleResponse(request http.Request) (string, error)
}

type HandleResponseFunc func(request http.Request, options ...interface{}) (string, error)
