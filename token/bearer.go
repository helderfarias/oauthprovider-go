package token

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/util"
	"regexp"
	"strings"
)

type BearerTokenType struct {
}

func (b *BearerTokenType) CreateResponse(accessToken *model.AccessToken) encode.Message {
	msg := &encode.OAuthMessage{}
	msg.TokenType = util.OAUTH_HEADER_NAME
	msg.AccessToken = accessToken.Token
	msg.ExpiresIn = accessToken.ExpiresAtInMilliseconds()
	return msg
}

func (b *BearerTokenType) GetAccessTokenInHeader(request http.Request) string {
	authzHeader := request.GetHeader(util.AUTHORIZATION)

	if authzHeader == "" {
		return ""
	}

	re := regexp.MustCompile("(?P<s1>\\w+) (?P<s2>\\w+)")
	if re.MatchString(authzHeader) {
		str1 := re.ReplaceAllString(authzHeader, "${s1}")
		str2 := re.ReplaceAllString(authzHeader, "${s2}")
		if strings.EqualFold(util.OAUTH_HEADER_NAME, str1) {
			return str2
		}
	}

	return ""
}
