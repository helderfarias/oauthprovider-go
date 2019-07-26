package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	. "github.com/helderfarias/oauthprovider-go/log"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
)

type refreshTokenGrant struct {
	server server.Authorizable
	before HandleResponseFunc
	after  HandleResponseFunc
}

type RefreshTokenGrantOption func(*refreshTokenGrant)

func NewRefreshTokenGrant(opts ...RefreshTokenGrantOption) *refreshTokenGrant {
	s := &refreshTokenGrant{}

	for _, o := range opts {
		o(s)
	}

	return s
}

func RefreshTokenGrantAfter(fn HandleResponseFunc) RefreshTokenGrantOption {
	return func(a *refreshTokenGrant) {
		a.after = fn
	}
}

func RefreshTokenGrantBefore(fn HandleResponseFunc) RefreshTokenGrantOption {
	return func(a *refreshTokenGrant) {
		a.before = fn
	}
}

func (p *refreshTokenGrant) SetServer(server server.Authorizable) {
	p.server = server
}

func (p *refreshTokenGrant) Identifier() string {
	return util.OAUTH_REFRESH_TOKEN
}

func (p *refreshTokenGrant) HandleResponse(request http.Request) (encode.Message, error) {
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

	if oldRefreshToken.Expired(token.REFRESH_TOKEN_VALIDITY_SECONDS) {
		return nil, util.NewInvalidRefreshError()
	}

	Logger.Info("%s", oldRefreshToken)

	if p.before != nil {
		if err := p.before(request); err != nil {
			return nil, err
		}
	}

	if err := p.server.DeleteTokens(oldRefreshToken, oldRefreshToken.AccessToken); err != nil {
		Logger.Error("DeleteTokens error", err)
		return nil, err
	}

	user := oldRefreshToken.AccessToken.User

	accessToken, err := p.createAccessToken(client, user)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	refreshToken, err := p.createRefreshToken(client, user, accessToken)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	if p.after != nil {
		if err := p.after(request, accessToken, refreshToken, oldRefreshToken); err != nil {
			return nil, err
		}
	}

	return p.server.CreateResponse(accessToken, refreshToken), nil
}

func (p *refreshTokenGrant) createAccessToken(client *model.Client, user *model.User) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}
	accessToken.Token = p.server.CreateToken(client, []string{})
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client
	accessToken.User = user

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (p *refreshTokenGrant) createRefreshToken(client *model.Client, user *model.User, accessToken *model.AccessToken) (*model.RefreshToken, error) {
	if p.server.HasGrantType(util.OAUTH_REFRESH_TOKEN) {
		refreshToken := &model.RefreshToken{}
		refreshToken.Token = p.server.CreateRefreshToken(client, []string{})
		refreshToken.ExpiresAt = p.server.IssuerExpireTimeForRefreshToken()
		refreshToken.Client = client
		refreshToken.User = user
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
