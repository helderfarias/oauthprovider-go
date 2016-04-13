package memory

import (
	"errors"
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type MemoryScopeStorage struct {
}

var scopeRepository map[string]*model.Scope
var scopeSafeInit sync.Once

func init() {
	scopeSafeInit.Do(func() {
		scopeRepository = make(map[string]*model.Scope, 0)
	})
}

func (c *MemoryScopeStorage) Find(scope, clientId string) (*model.Scope, error) {
	for _, v := range scopeRepository {
		if v.Name == scope {
			return v, nil
		}
	}

	return nil, errors.New("invalid")
}
