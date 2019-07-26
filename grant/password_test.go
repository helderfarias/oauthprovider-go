package grant

import (
	"testing"

	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/stretchr/testify/assert"
)

func TestCreate(t *testing.T) {
	grant := &passwordGrant{}

	assert.NotNil(t, grant)
}

func TestShouldBeCreateMessageForOnlyAccessToken(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := &passwordGrant{}
	grant.callback = func(userName, password string) *model.User { return &model.User{} }
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = "user"
	req.param["password"] = "user00"
	server.credencials = &model.Client{Name: "client", Secret: "secret"}

	message, _ := grant.HandleResponse(req)

	assert.NotNil(t, message)
	assert.Equal(t, message.Encode(), "{\"access_token\":\"token00\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
}

func TestErrorIfClientIdNullWhenHandleReponse(t *testing.T) {
	grant := &passwordGrant{}
	req := NewRequest()

	req.param["clientId"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfClientSecretNullWhenHandleReponse(t *testing.T) {
	grant := &passwordGrant{}
	req := NewRequest()

	req.param["clientId"] = "client"
	req.param["clientSecret"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfClientNotExistsWhenHandleReponse(t *testing.T) {
	grant := &passwordGrant{}
	grant.callback = func(userName, password string) *model.User { return &model.User{} }
	grant.server = &FakeServer{}
	req := NewRequest()

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = nil

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfUserNameNullWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := &passwordGrant{}
	grant.callback = func(userName, password string) *model.User { return &model.User{} }
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfPasswordNullWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := &passwordGrant{}
	grant.callback = func(userName, password string) *model.User { return &model.User{} }
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = "username"
	req.param["password"] = ""

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfcallBackNullWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := &passwordGrant{}
	grant.callback = func(userName, password string) *model.User { return nil }
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", "secret"}
	req.param["username"] = "username"
	req.param["password"] = "password"
	server.credencials = &model.Client{Name: "client", Secret: "secret"}

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}

func TestErrorIfInvalidAuthorizationHashWhenHandleReponse(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := &passwordGrant{}
	grant.callback = func(userName, password string) *model.User { return &model.User{} }
	grant.server = server

	req.param["clientId"] = "client"
	req.param["clientSecret"] = "secret"
	req.authz = []string{"client", ""}

	_, err := grant.HandleResponse(req)

	assert.NotNil(t, err)
}
