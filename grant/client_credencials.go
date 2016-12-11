package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type ClientCredencial struct {
	server servertype.Authorizable
}

func (p *ClientCredencial) SetServer(server servertype.Authorizable) {
	p.server = server
}

func (p *ClientCredencial) Identifier() string {
	return util.OAUTH_CLIENT_CREDENTIALS
}

func (p *ClientCredencial) HandleResponse(request http.Request) (encode.Message, error) {
	authorization := request.GetAuthorizationBasic()
	if authorization == nil ||
		authorization[0] == "" ||
		authorization[1] == "" {
		return nil, util.NewBadCredentialsError()
	}

	clientId := authorization[0]
	clientSecret := authorization[1]

	client := p.server.FindByCredencials(clientId, clientSecret)
	if client == nil {
		return nil, util.NewInvalidClientError()
	}

	scopes, err := p.server.CheckScope(request, client.Name)
	if err != nil {
		return nil, util.NewInvalidScopeError()
	}

	accessToken, err := p.createAccessToken(client, scopes)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	return p.server.CreateResponse(accessToken, nil), nil
}

func (p *ClientCredencial) createAccessToken(client *model.Client, scopes []string) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.CreateToken(client, nil, scopes)
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}
