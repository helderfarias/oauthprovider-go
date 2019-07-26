package authorization

import (
	"strings"
	"testing"

	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/util"
	"github.com/stretchr/testify/assert"
)

func TestShouldCreateAuthzCodeForPost(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := NewAuthorizationCode()
	grant.SetServer(server)

	server.credencials = &model.Client{
		Name:        "client",
		Secret:      "secret",
		RedirectUri: "http://localhost",
	}

	req.authz = append(req.authz, "client")
	req.authz = append(req.authz, "secret")

	result, err := grant.HandleResponse(req)

	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(result, "http://localhost?code="))
}

func TestShouldCreateAuthzCodeForBasic(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := NewAuthorizationCode(AuthorizationCodeTokenAuthMethd(util.Basic))
	grant.SetServer(server)

	server.credencials = &model.Client{
		Name:        "client",
		Secret:      "secret",
		RedirectUri: "http://localhost",
	}

	req.param["client_id"] = "client"

	result, err := grant.HandleResponse(req)

	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(result, "http://localhost?code="))
}

func TestShouldCreateAuthzCodeForPCKE256(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := NewAuthorizationCode(AuthorizationCodeTokenAuthMethd(util.NonePKCE))
	grant.SetServer(server)

	server.credencials = &model.Client{
		Name:        "client",
		Secret:      "secret",
		RedirectUri: "http://localhost",
	}

	req.param["client_id"] = "client"
	req.param["client_secret"] = "secret"
	req.param["code_challenge"] = "secret"
	req.param["code_challenge_method"] = "S256"

	result, err := grant.HandleResponse(req)

	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(result, "http://localhost?code="))
}

func TestShouldCreateAuthzCodeForPCKE512(t *testing.T) {
	server := NewServer()
	req := NewRequest()
	grant := NewAuthorizationCode(AuthorizationCodeTokenAuthMethd(util.NonePKCE))
	grant.SetServer(server)

	server.credencials = &model.Client{
		Name:        "client",
		Secret:      "secret",
		RedirectUri: "http://localhost",
	}

	req.param["client_id"] = "client"
	req.param["client_secret"] = "secret"
	req.param["code_challenge"] = "secret"
	req.param["code_challenge_method"] = "S512"

	result, err := grant.HandleResponse(req)

	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(result, "http://localhost?code="))
}
