package memory

import (
	"github.com/helderfarias/oauthprovider-go/model"
	"sync"
)

type MemoryRefreshTokenStorage struct {
}

var refreshTokenRepository map[string]*model.RefreshToken
var refreshTokenSafeInit sync.Once

func init() {
	refreshTokenSafeInit.Do(func() {
		refreshTokenRepository = make(map[string]*model.RefreshToken, 0)
	})
}

func (c *MemoryRefreshTokenStorage) Save(entity *model.RefreshToken) error {
	refreshTokenRepository[entity.Token] = entity
	return nil
}

func (c *MemoryRefreshTokenStorage) FindById(id string) *model.RefreshToken {
	return refreshTokenRepository[id]
}

func (c *MemoryRefreshTokenStorage) Delete(entity *model.RefreshToken) error {
	delete(refreshTokenRepository, entity.Token)
	return nil
}

func (m *MemoryRefreshTokenStorage) DeleteByAccessToken(AccessToken *model.AccessToken) error {
	return nil
}
