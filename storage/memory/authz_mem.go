package memory

import (
	"errors"
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type MemoryAuthzCodeStorage struct {
}

var authzCodeRepository map[string]*model.AuthzCode
var authzCodeSafeInit sync.Once

func init() {
	authzCodeSafeInit.Do(func() {
		authzCodeRepository = make(map[string]*model.AuthzCode, 0)
	})
}

func (m *MemoryAuthzCodeStorage) Save(entity *model.AuthzCode) error {
	authzCodeRepository[entity.Code] = entity
	return nil
}

func (c *MemoryAuthzCodeStorage) Find(code, clientId string) (*model.AuthzCode, error) {
	for _, v := range authzCodeRepository {
		if v.Code == code {
			return v, nil
		}
	}

	return nil, errors.New("invalid")
}
