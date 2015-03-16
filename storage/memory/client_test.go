package memory

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateMemoryClient(t *testing.T) {
	storage := &MemoryClientStorage{}

	assert.NotNil(t, storage)
}

func TestSaveMemoryClient(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{}

	storage.Save(entity)

	assert.NotEmpty(t, clientRepository)
}

func TestFindByCredencialsMemoryClient(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{Name: "client", Secret: "client00"}
	clientRepository[entity.Name] = entity

	ret := storage.FindByCredencials("client", "client00")

	assert.Equal(t, entity, ret)
}

func TestDeleteMemoryClient(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{Name: "client", Secret: "client00"}

	storage.Delete(entity)

	assert.Equal(t, 1, len(clientRepository))
}

func TestFindByIdMemoryClient(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{Name: "client", Secret: "client00"}
	clientRepository[entity.Name] = entity

	ret := storage.FindById("client")

	assert.Equal(t, entity, ret)
}
