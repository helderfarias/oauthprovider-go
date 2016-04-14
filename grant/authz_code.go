package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type AuthzCodeGrant struct {
	server servertype.Authorizable
}

func (p *AuthzCodeGrant) SetServer(server servertype.Authorizable) {
	p.server = server
}

func (p *AuthzCodeGrant) Identifier() string {
	return util.OAUTH_PASSWORD
}

func (p *AuthzCodeGrant) HandleResponse(request http.Request) (encode.Message, error) {
	clientId := request.GetClientId()
	if clientId == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_CLIENT_ID)
	}

	clientSecret := request.GetClientSecret()
	if clientSecret == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_CLIENT_SECRET)
	}

	authorization := request.GetAuthorizationBasic()
	if authorization == nil ||
		authorization[0] == "" ||
		authorization[1] == "" {
		return nil, util.NewBadCredentialsError()
	}

	if clientId != authorization[0] && clientSecret != authorization[1] {
		return nil, util.NewBadCredentialsError()
	}

	client := p.server.FindByCredencials(clientId, clientSecret)
	if client == nil {
		return nil, util.NewInvalidClientError()
	}

	code := request.GetAuthorizationCode()
	if code == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_AUTHORIZATION_CODE)
	}

	_, err := p.server.FindAuthzCode(code, clientId)
	if err != nil {
		return nil, util.NewInvalidRequestError(util.OAUTH_AUTHORIZATION_CODE)
	}

	accessToken, err := p.createAccessToken(client)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	refreshToken, err := p.createRefreshToken(client, accessToken)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	return p.server.CreateResponse(accessToken, refreshToken), nil
}

func (p *AuthzCodeGrant) createAccessToken(client *model.Client) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.CreateToken()
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (p *AuthzCodeGrant) createRefreshToken(client *model.Client, accessToken *model.AccessToken) (*model.RefreshToken, error) {
	if p.server.HasGrantType(util.OAUTH_REFRESH_TOKEN) {
		refreshToken := &model.RefreshToken{}
		refreshToken.Token = p.server.CreateToken()
		refreshToken.ExpiresAt = p.server.IssuerExpireTimeForRefreshToken()
		refreshToken.Client = client
		refreshToken.AccessToken = accessToken

		err := p.server.StoreRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}

		return refreshToken, nil
	}

	return nil, nil
}
