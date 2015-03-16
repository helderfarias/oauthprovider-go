package http

import (
	"encoding/base64"
	"github.com/helderfarias/oauthprovider-go/util"
	"log"
	"net/http"
	"strings"
)

type OAuthRequest struct {
	HttpRequest *http.Request
}

func (o *OAuthRequest) GetParam(key string) string {
	return o.HttpRequest.PostFormValue(key)
}

func (o *OAuthRequest) GetHeader(key string) string {
	return o.HttpRequest.Header.Get(key)
}

func (o *OAuthRequest) GetClientId() string {
	header := o.GetHeader(util.AUTHORIZATION)
	credencials := o.decodeHeader(header)

	if credencials != nil {
		return credencials[0]
	}

	return o.GetParam(util.OAUTH_CLIENT_ID)
}

func (o *OAuthRequest) GetClientSecret() string {
	header := o.GetHeader(util.AUTHORIZATION)
	credencials := o.decodeHeader(header)

	if credencials != nil {
		return credencials[1]
	}

	return o.GetParam(util.OAUTH_CLIENT_SECRET)
}

func (o *OAuthRequest) GetUserName() string {
	return o.GetParam(util.OAUTH_USERNAME)
}

func (o *OAuthRequest) GetPassword() string {
	return o.GetParam(util.OAUTH_PASSWORD)
}

func (o *OAuthRequest) GetGrantType() string {
	return o.GetParam(util.OAUTH_GRANT_TYPE)
}

func (o *OAuthRequest) GetRefreshToken() string {
	return o.GetParam(util.OAUTH_REFRESH_TOKEN)
}

func (o *OAuthRequest) GetAuthorizationBasic() []string {
	header := o.GetHeader(util.AUTHORIZATION)
	return o.decodeHeader(header)
}

func (o *OAuthRequest) GetRevokeToken() string {
	return o.GetParam(util.OAUTH_REVOKE_TOKEN)
}

func (o *OAuthRequest) decodeHeader(header string) []string {
	if header == "" {
		return nil
	}

	tokens := strings.Split(header, " ")
	if len(tokens) == 0 {
		return nil
	}

	if authType := tokens[0]; strings.ToLower(authType) != "basic" {
		return nil
	}

	if encode := tokens[1]; encode != "" {
		bytes, err := base64.StdEncoding.DecodeString(encode)
		if err != nil {
			log.Println(err)
			return nil
		}

		decode := string(bytes)
		if strings.Contains(decode, ":") && len(strings.Split(decode, ":")) == 2 {
			creds := strings.Split(decode, ":")
			if creds[0] != "" && creds[1] != "" {
				return creds
			}
		}
	}

	return nil
}
