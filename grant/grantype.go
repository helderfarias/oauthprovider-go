package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
)

type GrantType interface {
	Identifier() string

	HandleResponse(request http.Request) encode.Message
}
