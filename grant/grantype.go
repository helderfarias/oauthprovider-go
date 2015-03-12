package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server"
)

type GrantType interface {
	Identifier() string

	SetServer(server server.Authorizable)

	HandleResponse(request http.Request) encode.Message
}
