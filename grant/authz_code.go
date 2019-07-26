package grant

import (
	"net/url"

	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	. "github.com/helderfarias/oauthprovider-go/log"
	"github.com/helderfarias/oauthprovider-go/model"
	servertype "github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type authzCodeGrant struct {
	server servertype.Authorizable
	before HandleResponseFunc
	after  HandleResponseFunc
}

type AuthzCodeGrantOption func(*authzCodeGrant)

func NewAuthzCodeGrant(opts ...AuthzCodeGrantOption) *authzCodeGrant {
	s := &authzCodeGrant{}

	for _, o := range opts {
		o(s)
	}

	return s
}

func AuthzCodeGrantAfter(fn HandleResponseFunc) AuthzCodeGrantOption {
	return func(a *authzCodeGrant) {
		a.after = fn
	}
}

func AuthzCodeGrantBefore(fn HandleResponseFunc) AuthzCodeGrantOption {
	return func(a *authzCodeGrant) {
		a.before = fn
	}
}

func (p *authzCodeGrant) SetServer(server servertype.Authorizable) {
	p.server = server
}

func (p *authzCodeGrant) Identifier() string {
	return util.OAUTH_AUTHORIZATION_CODE
}

func (p *authzCodeGrant) HandleResponse(request http.Request) (encode.Message, error) {
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
		Logger.Debug("Client not found: %s, %s", clientId, clientSecret)
		return nil, util.NewInvalidClientError()
	}

	redirectUri := request.GetParam(util.OAUTH_REDIRECT_URI)
	_, err := url.QueryUnescape(redirectUri)
	if err != nil {
		return nil, util.NewInvalidRequestError(redirectUri)
	}

	if client.RedirectUri == redirectUri {
		return nil, util.NewInvalidRequestError(redirectUri)
	}

	code := request.GetParam(util.OAUTH_CODE)
	if code == "" {
		Logger.Debug("Authorization Code not found: %s", code)
		return nil, util.NewInvalidRequestError(util.OAUTH_CODE)
	}

	result, err := p.server.FindAuthzCode(code, clientId)
	if err != nil {
		Logger.Error("Authorization Code not found in storage: %s", err)
		return nil, util.NewInvalidRequestError(util.OAUTH_CODE)
	}

	if result.Expired() {
		Logger.Error("Authorization Code has expired: %s", result.Code)
		return nil, util.NewUnauthorizedClientError()
	}

	if p.before != nil {
		if err := p.before(request); err != nil {
			return nil, err
		}
	}

	accessToken, err := p.createAccessToken(client)
	if err != nil {
		Logger.Error("Error on create token: %s", err)
		return nil, util.NewOAuthRuntimeError()
	}

	refreshToken, err := p.createRefreshToken(client, accessToken)
	if err != nil {
		Logger.Error("Error on create refresh: %s", err)
		return nil, util.NewOAuthRuntimeError()
	}

	if p.after != nil {
		if err := p.after(request, accessToken, refreshToken); err != nil {
			return nil, err
		}
	}

	return p.server.CreateResponse(accessToken, refreshToken), nil
}

func (p *authzCodeGrant) createAccessToken(client *model.Client) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.CreateToken(client, []string{})
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (p *authzCodeGrant) createRefreshToken(client *model.Client, accessToken *model.AccessToken) (*model.RefreshToken, error) {
	if p.server.HasGrantType(util.OAUTH_REFRESH_TOKEN) {
		refreshToken := &model.RefreshToken{}
		refreshToken.Token = p.server.CreateRefreshToken(client, []string{})
		refreshToken.ExpiresAt = p.server.IssuerExpireTimeForRefreshToken()
		refreshToken.Client = client
		refreshToken.AccessToken = accessToken

		if refreshToken.Token == "" {
			return nil, nil
		}

		err := p.server.StoreRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}

		return refreshToken, nil
	}

	return nil, nil
}
