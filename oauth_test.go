package oauthprovider

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreate(t *testing.T) {
	authz := New().AuthorizationServer()
	resource := New().ResourceServer()

	assert.NotNil(t, authz)
	assert.NotNil(t, resource)
}
