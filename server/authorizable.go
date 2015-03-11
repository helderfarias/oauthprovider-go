package server

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/model"
	"time"
)

type Authorizable interface {
	FindByCredencials(clientId, clientSecret string) *model.Client

	IssuerAccessToken() string

	IssuerExpireTimeForAccessToken() time.Time

	StoreAccessToken(accessToken *model.AccessToken)

	CreateResponse(accessToken *model.AccessToken) encode.Message
}
