package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenConverterJwt struct {
	ExpiryTimeInSecondsForAccessToken int
	PayloadHandler                    func() map[string]interface{}
	PrivateKey                        []byte
}

func (this *TokenConverterJwt) AccessToken() string {
	ecdsaKey, err := jwt.ParseECPrivateKeyFromPEM(this.PrivateKey)
	if err != nil {
		panic(err)
	}

	tokenHandler := jwt.New(jwt.SigningMethodES512)

	for key, value := range this.PayloadHandler() {
		tokenHandler.Claims[key] = value
	}

	tokenHandler.Claims["exp"] = this.expiresAtInMilliseconds()

	token, err := tokenHandler.SignedString(ecdsaKey)
	if err != nil {
		panic(err)
	}

	return token
}

func (o *TokenConverterJwt) RefreshToken() string {
	return ""
}

func (o *TokenConverterJwt) CreateExpireTimeForAccessToken() time.Time {
	return o.calculateExpiryTime(o.ExpiryTimeInSecondsForAccessToken)
}

func (o *TokenConverterJwt) CreateExpireTimeForRefreshToken() time.Time {
	return o.calculateExpiryTime(0)
}

func (o *TokenConverterJwt) calculateExpiryTime(daysInSeconds int) time.Time {
	expiresAt := time.Now()
	expiresAt = expiresAt.Add(time.Duration(daysInSeconds) * time.Second)
	return expiresAt
}

func (a *TokenConverterJwt) expiresAtInMilliseconds() int64 {
	expiresAt := a.CreateExpireTimeForAccessToken()

	if expiresAt.IsZero() {
		return 0
	}

	return expiresAt.UnixNano() / int64(time.Millisecond)
}
