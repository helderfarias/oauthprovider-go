package servertype

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"time"
)

type Authorizable interface {
	FindAuthzCode(code, clientId string) (*model.AuthzCode, error)

	FindScope(scope, clientId string) (*model.Scope, error)

	FindClientById(clientId string) *model.Client

	FindByCredencials(clientId, clientSecret string) *model.Client

	FindRefreshTokenById(refreshToken string) *model.RefreshToken

	CreateToken() string

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

	HandlerAuthorize(request http.Request, response http.Response) (string, error)

	HandlerAccessToken(request http.Request) (string, error)

	HandlerRevokeToken(request http.Request) error
}
