package memory

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreate(t *testing.T) {
	storage := &MemoryClientStorage{}

	assert.NotNil(t, storage)
}

func TestSave(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{}

	storage.Save(entity)

	assert.NotEmpty(t, repository)
}

func TestFindByCredencials(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{Name: "client", Secret: "client00"}
	repository[entity.Name] = entity

	ret := storage.FindByCredencials("client", "client00")

	assert.Equal(t, entity, ret)
}

func TestDelete(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{Name: "client", Secret: "client00"}

	storage.Delete(entity)

	assert.Equal(t, 1, len(repository))
}

func TestFindById(t *testing.T) {
	storage := &MemoryClientStorage{}
	entity := &model.Client{Name: "client", Secret: "client00"}
	repository[entity.Name] = entity

	ret := storage.FindById("client")

	assert.Equal(t, entity, ret)
}
