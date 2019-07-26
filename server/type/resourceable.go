package servertype

import (
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
)

type Resourceable interface {
	GetAccessToken(request http.Request) (string, error)

	ValidateRequest(request http.Request) (*model.AccessToken, error)
}
