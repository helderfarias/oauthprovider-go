package token

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
)

type TokenType interface {
	CreateResponse(accessToken *model.AccessToken, refreshToken *model.RefreshToken) encode.Message

	GetAccessTokenInHeader(request http.Request) string
}
