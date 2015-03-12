package storage

import (
	"github.com/helderfarias/oauthprovider-go/model"
)

type ClientStorage interface {
	Save(entity *model.Client)

	FindById(id string) *model.Client

	Delete(entity *model.Client)

	FindByCredencials(clientId, clientSecret string) *model.Client
}

type AccessTokenStorage interface {
	Save(entity *model.AccessToken)

	FindById(id string) *model.AccessToken

	Delete(entity *model.AccessToken)
}

type RefreshTokenStorage interface {
	Save(entity *model.RefreshToken)

	FindById(id string) *model.RefreshToken

	Delete(entity *model.RefreshToken)

	DeleteByAccessToken(AccessToken *model.AccessToken)
}
