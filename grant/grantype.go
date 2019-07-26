package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	servertype "github.com/helderfarias/oauthprovider-go/server/type"
)

type GrantType interface {
	Identifier() string

	SetServer(server servertype.Authorizable)

	HandleResponse(request http.Request) (encode.Message, error)
}

type HandleResponseFunc func(request http.Request, options ...interface{}) error
