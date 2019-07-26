package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/util"
)

type passwordGrant struct {
	server   server.Authorizable
	callback UserPasswordCallback
	before   HandleResponseFunc
	after    HandleResponseFunc
}

type UserPasswordCallback func(userName, password string) *model.User

type PasswordGrantOption func(*passwordGrant)

func NewPasswordGrant(opts ...PasswordGrantOption) *passwordGrant {
	s := &passwordGrant{}

	for _, o := range opts {
		o(s)
	}

	return s
}

func PasswordGrantCallback(fn UserPasswordCallback) PasswordGrantOption {
	return func(a *passwordGrant) {
		a.callback = fn
	}
}

func PasswordGrantAfter(fn HandleResponseFunc) PasswordGrantOption {
	return func(a *passwordGrant) {
		a.after = fn
	}
}

func PasswordGrantBefore(fn HandleResponseFunc) PasswordGrantOption {
	return func(a *passwordGrant) {
		a.before = fn
	}
}

func (p *passwordGrant) SetServer(server server.Authorizable) {
	p.server = server
}

func (p *passwordGrant) Identifier() string {
	return util.OAUTH_PASSWORD
}

func (p *passwordGrant) HandleResponse(request http.Request) (encode.Message, error) {
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

	userName := request.GetUserName()
	if userName == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_USERNAME)
	}

	password := request.GetPassword()
	if password == "" {
		return nil, util.NewInvalidRequestError(util.OAUTH_PASSWORD)
	}

	user := p.callback(userName, password)
	if user == nil {
		return nil, util.NewInvalidCredentialsError()
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

	accessToken, err := p.createAccessToken(client, user, scopes)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	refreshToken, err := p.createRefreshToken(client, user, scopes, accessToken)
	if err != nil {
		return nil, util.NewOAuthRuntimeError()
	}

	if p.after != nil {
		if err := p.after(request, accessToken, refreshToken); err != nil {
			return nil, err
		}
	}

	return p.server.CreateResponse(accessToken, refreshToken), nil
}

func (p *passwordGrant) createAccessToken(client *model.Client, user *model.User, scopes []string) (*model.AccessToken, error) {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.CreateToken(client, scopes)
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client
	accessToken.User = user

	err := p.server.StoreAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (p *passwordGrant) createRefreshToken(client *model.Client, user *model.User, scopes []string, accessToken *model.AccessToken) (*model.RefreshToken, error) {
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
