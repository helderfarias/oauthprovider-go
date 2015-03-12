package servertype

import (
	"github.com/helderfarias/oauthprovider-go/http"
)

type Resourceable interface {
	ValidateRequest(request http.Request) error
}
