package scope

import (
	"github.com/helderfarias/oauthprovider-go/http"
)

type Validator interface {
	Execute(request http.Request, clientId string) ([]string, error)
}
