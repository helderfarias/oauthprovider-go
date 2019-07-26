package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/util"
)

type clientCredencial struct {
	server server.Authorizable
	before HandleResponseFunc
	after  HandleResponseFunc
}

type ClientCredencialOption func(*clientCredencial)

func NewClientCredencial(opts ...ClientCredencialOption) *clientCredencial {
	s := &clientCredencial{}

	for _, o := range opts {
		o(s)
	}

	return s
}

func ClientCredencialAfter(fn HandleResponseFunc) ClientCredencialOption {
	return func(a *clientCredencial) {
		a.after = fn
	}
}

func ClientCredencialBefore(fn HandleResponseFunc) ClientCredencialOption {
	return func(a *clientCredencial) {
		a.before = fn
	}
}

func (p *clientCredencial) SetServer(server server.Authorizable) {
	p.server = server
}

func (p *clientCredencial) Identifier() string {
	return util.OAUTH_CLIENT_CREDENTIALS
}

func (p *clientCredencial) HandleResponse(request http.Request) (encode.Message, error) {
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

	if p.before != nil {
		if err := p.before(request); err != nil {
			return nil, err
		}
	}

	accessToken, err := p.createAccessToken(client, scopes)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	if p.after != nil {
		if err := p.after(request, accessToken); err != nil {
			return nil, err
		}
	}

	return p.server.CreateResponse(accessToken, nil), nil
}

func (p *clientCredencial) createAccessToken(client *model.Client, scopes []string) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.CreateToken(client, scopes)
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}
