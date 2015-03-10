package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInvalidAccessTokenError(t *testing.T) {
	err := NewInvalidAccessTokenError()

	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "{\"error\":\"The access token is invalid.\"}")
	assert.Equal(t, err.StatusCode, 400)
	assert.Equal(t, err.ErrorType, "The access token is invalid.")
	assert.Equal(t, err.GrantType, "invalid_request")
}

func TestInvalidRequestError(t *testing.T) {
	err := NewInvalidRequestError("grant_type")

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "'grant_type'")
	assert.Equal(t, err.StatusCode, 400)
	assert.Contains(t, err.ErrorType, "'grant_type'")
	assert.Equal(t, err.GrantType, "invalid_request")
}

func TestUnSupportedGrantTypeError(t *testing.T) {
	err := NewUnSupportedGrantTypeError("grant_type")

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "'grant_type'")
	assert.Equal(t, err.StatusCode, 400)
	assert.Contains(t, err.ErrorType, "'grant_type'")
	assert.Equal(t, err.GrantType, "unsupported_grant_type")
}
