package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type RefreshTokenGrant struct {
	callback VerifyCredentialsCallback
	server   servertype.Authorizable
}

func (p *RefreshTokenGrant) Identifier() string {
	return util.OAUTH_PASSWORD
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

	p.server.DeleteTokens(oldRefreshToken, oldRefreshToken.AccessToken)

	user := oldRefreshToken.AccessToken.User

	accessToken := p.createAccessToken(client, user)

	refreshToken := p.createRefreshToken(client, user, accessToken)

	return p.server.CreateResponse(accessToken, refreshToken), nil
}

func (p *RefreshTokenGrant) createAccessToken(client *model.Client, user *model.User) *model.AccessToken {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.IssuerAccessToken()
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client
	accessToken.User = user

	p.server.StoreAccessToken(accessToken)
	return accessToken
}

func (p *RefreshTokenGrant) createRefreshToken(client *model.Client, user *model.User, accessToken *model.AccessToken) *model.RefreshToken {
	if p.server.HasGrantType(util.OAUTH_REFRESH_TOKEN) {
		refreshToken := &model.RefreshToken{}
		refreshToken.Token = p.server.IssuerAccessToken()
		refreshToken.ExpiresAt = p.server.IssuerExpireTimeForRefreshToken()
		refreshToken.Client = client
		refreshToken.User = user
		refreshToken.AccessToken = accessToken
		p.server.StoreRefreshToken(refreshToken)
		return refreshToken
	}

	return nil
}
