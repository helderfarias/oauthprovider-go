package encode

import (
	"encoding/json"
)

type OAuthMessage struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

type encodeAccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type encodeRefreshToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (o *OAuthMessage) Encode() string {
	var output interface{}

	if o.RefreshToken != "" {
		output = &encodeRefreshToken{
			AccessToken:  o.AccessToken,
			RefreshToken: o.RefreshToken,
			TokenType:    o.TokenType,
			ExpiresIn:    o.ExpiresIn,
		}
	} else {
		output = &encodeAccessToken{
			AccessToken: o.AccessToken,
			TokenType:   o.TokenType,
			ExpiresIn:   o.ExpiresIn,
		}
	}

	bytes, err := json.Marshal(output)
	if err != nil {
		return ""
	}

	return string(bytes)
}
