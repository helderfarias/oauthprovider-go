package storage

import (
	"github.com/helderfarias/oauthprovider-go/model"
)

type ClientStorage interface {
	Save(entity *model.Client) error

	FindById(id string) *model.Client

	Delete(entity *model.Client) error

	FindByCredencials(clientId, clientSecret string) *model.Client
}

type AccessTokenStorage interface {
	Save(entity *model.AccessToken) error

	FindById(id string) *model.AccessToken

	Delete(entity *model.AccessToken) error
}

type RefreshTokenStorage interface {
	Save(entity *model.RefreshToken) error

	FindById(id string) *model.RefreshToken

	Delete(entity *model.RefreshToken) error

	DeleteByAccessToken(AccessToken *model.AccessToken) error
}

type ScopeStorage interface {
	Find(scope, clientId string) (*model.Scope, error)
}
