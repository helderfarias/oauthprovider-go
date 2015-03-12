package memory

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type MemoryAccessTokenStorage struct {
}

var accessTokenRepository map[string]*model.AccessToken
var accessTokenSafeInit sync.Once

func init() {
	accessTokenSafeInit.Do(func() {
		accessTokenRepository = make(map[string]*model.AccessToken, 0)
	})
}

func (c *MemoryAccessTokenStorage) Save(entity *model.AccessToken) {
	accessTokenRepository[entity.Token] = entity
}

func (c *MemoryAccessTokenStorage) FindById(id string) *model.AccessToken {
	return accessTokenRepository[id]
}

func (c *MemoryAccessTokenStorage) Delete(entity *model.AccessToken) {
	delete(accessTokenRepository, entity.Token)
}
