package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server/type"
)

type GrantType interface {
	Identifier() string

	SetServer(server servertype.Authorizable)

	HandleResponse(request http.Request) encode.Message
}
