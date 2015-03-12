package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/util"
)

type PasswordGrant struct {
	callback VerifyCredentialsCallback
	server   server.Authorizable
}

func (p *PasswordGrant) Identifier() string {
	return util.OAUTH_PASSWORD
}

func (p *PasswordGrant) HandleResponse(request http.Request) (encode.Message, error) {
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

	user := p.callback.Find(userName, password)
	if user == nil {
		return nil, util.NewInvalidCredentialsError()
	}

	accessToken := p.createAccessToken(client, user)

	return p.server.CreateResponse(accessToken), nil
}

func (p *PasswordGrant) createAccessToken(client *model.Client, user *model.User) *model.AccessToken {
	accessToken := &model.AccessToken{}

	accessToken.Token = p.server.IssuerAccessToken()
	accessToken.ExpiresAt = p.server.IssuerExpireTimeForAccessToken()
	accessToken.Client = client
	accessToken.User = user

	p.server.StoreAccessToken(accessToken)
	return accessToken
}
