package storage

import (
	"github.com/helderfarias/oauthprovider-go/model"
)

type ClientStorage interface {
	Save(entity *model.Client)

	FindById(id float64) *model.Client

	Delete(entity *model.Client)

	FindByCredencials(clientId, clientSecret string) *model.Client
}
