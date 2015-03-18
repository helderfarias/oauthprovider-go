package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/logger"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type RefreshTokenGrant struct {
	callback VerifyCredentialsCallback
	server   servertype.Authorizable
}

func (p *RefreshTokenGrant) SetServer(server servertype.Authorizable) {
	p.server = server
}

func (p *RefreshTokenGrant) Identifier() string {
	return util.OAUTH_REFRESH_TOKEN
}

func (p *RefreshTokenGrant) HandleResponse(request http.Request) (encode.Message, error) {
	clientId := request.GetClientId()
	if clientId == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_CLIENT_ID)
	}

	clientSecret := request.GetClientSecret()
	if clientSecret == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_CLIENT_SECRET)
	}

	authz := request.GetAuthorizationBasic()
	if authz == nil ||
		authz[0] == "" ||
		authz[1] == "" {
		return nil, util.NewBadCredentialsError()
	}

	if request.GetRefreshToken() == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_REFRESH_TOKEN)
	}

	if clientId != authz[0] && clientSecret != authz[1] {
		return nil, util.NewBadCredentialsError()
	}

	client := p.server.FindByCredencials(clientId, clientSecret)
	if client == nil {
		return nil, util.NewInvalidClientError()
	}

	oldRefreshToken := p.server.FindRefreshTokenById(request.GetRefreshToken())
	if oldRefreshToken == nil {
		return nil, util.NewInvalidRefreshError()
	}

	if oldRefreshToken.Expired() {
		return nil, util.NewInvalidRefreshError()
	}

	logger.Info("%s", oldRefreshToken)

	p.server.DeleteTokens(oldRefreshToken, oldRefreshToken.AccessToken)

	user := oldRefreshToken.AccessToken.User

	accessToken, err := p.createAccessToken(client, user)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	refreshToken, err := p.createRefreshToken(client, user, accessToken)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	return p.server.CreateResponse(accessToken, refreshToken), nil
}

func (p *RefreshTokenGrant) createAccessToken(client *model.Client, user *model.User) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.IssuerAccessToken()
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client
	accessToken.User = user

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (p *RefreshTokenGrant) createRefreshToken(client *model.Client, user *model.User, accessToken *model.AccessToken) (*model.RefreshToken, error) {
	if p.server.HasGrantType(util.OAUTH_REFRESH_TOKEN) {
		refreshToken := &model.RefreshToken{}
		refreshToken.Token = p.server.IssuerAccessToken()
		refreshToken.ExpiresAt = p.server.IssuerExpireTimeForRefreshToken()
		refreshToken.Client = client
		refreshToken.User = user
		refreshToken.AccessToken = accessToken

		err := p.server.StoreRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}

		return refreshToken, nil
	}

	return nil, nil
}
