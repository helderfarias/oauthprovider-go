package memory

import (
	"errors"
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type PostgresScopeStorage struct {
}

func (c *PostgresScopeStorage) Find(scope, clientId string) (*model.Scope, error) {
	return nil, nil
}
