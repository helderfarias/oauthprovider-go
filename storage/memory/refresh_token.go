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

func (c *MemoryRefreshTokenStorage) Save(entity *model.RefreshToken) {
	refreshTokenRepository[entity.Token] = entity
}

func (c *MemoryRefreshTokenStorage) FindById(id string) *model.RefreshToken {
	return refreshTokenRepository[id]
}

func (c *MemoryRefreshTokenStorage) Delete(entity *model.RefreshToken) {
	delete(refreshTokenRepository, entity.Token)
}

func (m *MemoryRefreshTokenStorage) DeleteByAccessToken(AccessToken *model.AccessToken) {
}
