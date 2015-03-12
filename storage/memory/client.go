package memory

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type MemoryClientStorage struct {
}

var clientRepository map[string]*model.Client
var clientSafeInit sync.Once

func init() {
	clientSafeInit.Do(func() {
		clientRepository = make(map[string]*model.Client, 0)
	})
}

func (c *MemoryClientStorage) Save(entity *model.Client) {
	clientRepository[entity.Name] = entity
}

func (c *MemoryClientStorage) FindById(id string) *model.Client {
	return clientRepository[id]
}

func (c *MemoryClientStorage) Delete(entity *model.Client) {
	delete(clientRepository, entity.Name)
}

func (c *MemoryClientStorage) FindByCredencials(clientId, clientSecret string) *model.Client {
	for _, v := range clientRepository {
		if v.Name == clientId && v.Secret == clientSecret {
			return v
		}
	}

	return nil
}
