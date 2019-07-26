package authorization

import (
	"github.com/helderfarias/oauthprovider-go/http"
	servertype "github.com/helderfarias/oauthprovider-go/server/type"
)

type AuthorizeType interface {
	Identifier() string

	SetServer(server servertype.Authorizable)

	HandleResponse(request http.Request) (string, error)
}

type HandleResponseFunc func(request http.Request, options ...interface{}) (string, error)
