package encode

import (
	"encoding/json"
)

type OAuthMessage struct {
	AccessToken string  `json:"access_token"`
	TokenType   string  `json:"token_type"`
	ExpiresIn   float64 `json:"expires_in"`
}

func (o *OAuthMessage) Encode() string {
	bytes, err := json.Marshal(o)

	if err != nil {
		return ""
	}

	return string(bytes)
}
