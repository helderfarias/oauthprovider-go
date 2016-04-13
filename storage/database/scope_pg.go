package database

import (
	"github.com/helderfarias/oauthprovider-go/model"
)

type PostgresScopeStorage struct {
}

func (c *PostgresScopeStorage) Find(scope, clientId string) (*model.Scope, error) {
	return nil, nil
}
