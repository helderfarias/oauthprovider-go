package token

import (
	"encoding/base64"
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

	PUBLIC_KEY_BASE64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JR2JNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWpBNEdHQUFRQjBxaDY4VHpSSHBrT3F6WVJxSjVmY0FDMW51bWYNCmM2Ky9OemlPb0dDckV6c0JvWUZJUzNuWERNbElTYUdkbWE3VGtkdzBpNEMyV3ZkVUxOYVVDR3M5ZzZRQmZna1oNCkdvMVJpN0R5Z1l1b1RQQXJLeTRCTWZPVEczdXQ1c1lQaStUYzBzQ2tHKzJ3VmRvb2FtOEhhamprWmxJR015bFUNCmxpODB0bjhqZWJpR3V3WlZ1Q009DQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0J"

	PRIVATE_KEY_BASE64 = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tDQpNSUhjQWdFQkJFSUJlaWpOUmd0ejlqVFVOeHR2TFFoVi9hOEFmbTFOSFh5YmJzTWhQeTRNYzBMZVN0MmhlMkw0DQpZRHRtOHljUi95cDY3MVM1K3hZTlF0MTQya1FLelBvOGtmT2dCd1lGSzRFRUFDT2hnWWtEZ1lZQUJBSFNxSHJ4DQpQTkVlbVE2ck5oR29ubDl3QUxXZTZaOXpyNzgzT0k2Z1lLc1RPd0doZ1VoTGVkY015VWhKb1oyWnJ0T1IzRFNMDQpnTFphOTFRczFwUUlhejJEcEFGK0NSa2FqVkdMc1BLQmk2aE04Q3NyTGdFeDg1TWJlNjNteGcrTDVOelN3S1FiDQo3YkJWMmlocWJ3ZHFPT1JtVWdZektWU1dMelMyZnlONXVJYTdCbFc0SXc9PQ0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQ=="
)

func TestShouldBeCreateInstanceJwtToken(t *testing.T) {
	converter := &TokenConverterJwt{
		ExpiryTimeInSecondsForAccessToken: ACCESS_TOKEN_VALIDITY_SECONDS,
	}

	assert.NotNil(t, converter)
}

func TestShouldBeCreateJwtToken(t *testing.T) {
	data, _ := base64.StdEncoding.DecodeString(PRIVATE_KEY_BASE64)

	converter := &TokenConverterJwt{
		ExpiryTimeInSecondsForAccessToken: ACCESS_TOKEN_VALIDITY_SECONDS,
		PrivateKey:                        []byte(data),
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
