package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
)

type PasswordGrant struct {
}

func (p *PasswordGrant) Identifier() string {
	return ""
}

func (p *PasswordGrant) HandleResponse(request http.Request) encode.Message {
	accessToken := createAccessToken(client, user, scopes)

	refreshToken = createRefreshToken(client, user, accessToken)

	strategy := p.server.getTokenType()

	return strategy.createResponse(accessToken, refreshToken)
}
