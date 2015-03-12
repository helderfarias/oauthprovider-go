package memory

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type MemoryClientStorage struct {
}

var repository map[string]*model.Client
var safeInit sync.Once

func init() {
	safeInit.Do(func() {
		repository = make(map[string]*model.Client, 0)
	})
}

func (c *MemoryClientStorage) Save(entity *model.Client) {
	repository[entity.Name] = entity
}

func (c *MemoryClientStorage) FindById(id string) *model.Client {
	return repository[id]
}

func (c *MemoryClientStorage) Delete(entity *model.Client) {
	delete(repository, entity.Name)
}

func (c *MemoryClientStorage) FindByCredencials(clientId, clientSecret string) *model.Client {
	for _, v := range repository {
		if v.Name == clientId && v.Secret == clientSecret {
			return v
		}
	}

	return nil
}
