package token

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB0qh68TzRHpkOqzYRqJ5fcAC1numf
c6+/NziOoGCrEzsBoYFIS3nXDMlISaGdma7Tkdw0i4C2WvdULNaUCGs9g6QBfgkZ
Go1Ri7DygYuoTPArKy4BMfOTG3ut5sYPi+Tc0sCkG+2wVdooam8HajjkZlIGMylU
li80tn8jebiGuwZVuCM=
-----END PUBLIC KEY-----	
	`

	PRIVATE_KEY = `
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBeijNRgtz9jTUNxtvLQhV/a8Afm1NHXybbsMhPy4Mc0LeSt2he2L4
YDtm8ycR/yp671S5+xYNQt142kQKzPo8kfOgBwYFK4EEACOhgYkDgYYABAHSqHrx
PNEemQ6rNhGonl9wALWe6Z9zr783OI6gYKsTOwGhgUhLedcMyUhJoZ2ZrtOR3DSL
gLZa91Qs1pQIaz2DpAF+CRkajVGLsPKBi6hM8CsrLgEx85Mbe63mxg+L5NzSwKQb
7bBV2ihqbwdqOORmUgYzKVSWLzS2fyN5uIa7BlW4Iw==
-----END EC PRIVATE KEY-----	
	`
)

func TestShouldBeCreateInstanceJwtToken(t *testing.T) {
	converter := &TokenConverterJwt{
		ExpiryTimeInSecondsForAccessToken: ACCESS_TOKEN_VALIDITY_SECONDS,
	}

	assert.NotNil(t, converter)
}

func TestShouldBeCreateJwtToken(t *testing.T) {
	converter := &TokenConverterJwt{
		ExpiryTimeInSecondsForAccessToken: ACCESS_TOKEN_VALIDITY_SECONDS,
		PrivateKey:                        []byte(PRIVATE_KEY),
		PayloadHandler: func() map[string]interface{} {
			payload := map[string]interface{}{}
			payload["login"] = "login"
			payload["name"] = "name"
			payload["roles"] = "r1,r2,r3"
			return payload
		},
	}

	accessToken := converter.AccessToken()
	refreshToken := converter.RefreshToken()

	assert.NotNil(t, accessToken)
	assert.NotEmpty(t, accessToken)
	assert.Empty(t, refreshToken)
}
