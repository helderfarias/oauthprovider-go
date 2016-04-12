package servertype

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"time"
)

type Authorizable interface {
	FindScope(scope, clientId string) (*model.Scope, error)

	FindByCredencials(clientId, clientSecret string) *model.Client

	FindRefreshTokenById(refreshToken string) *model.RefreshToken

	IssuerAccessToken() string

	RevokeToken(request http.Request) error

	DeleteTokens(refreshToken *model.RefreshToken, accessToken *model.AccessToken) error

	IssuerExpireTimeForAccessToken() time.Time

	IssuerExpireTimeForRefreshToken() time.Time

	StoreAccessToken(token *model.AccessToken) error

	StoreRefreshToken(token *model.RefreshToken) error

	HasGrantType(identified string) bool

	CreateResponse(accessToken *model.AccessToken, refreshToken *model.RefreshToken) encode.Message

	CheckScope(request http.Request, clientId string) ([]string, error)

	IsScopeRequired() bool

	SetScopeRequired(value bool)

	GetDefaultScope() string
}
