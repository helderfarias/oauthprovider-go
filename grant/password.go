package grant

import (
	"github.com/helderfarias/oauthprovider-go/encode"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
	"log"
)

type PasswordGrant struct {
	server   servertype.Authorizable
	Callback func(userName, password string) *model.User
}

func (p *PasswordGrant) SetServer(server servertype.Authorizable) {
	p.server = server
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

	log.Println("[oauthprovider] PasswordGrant => HandleResponse: ", userName, password)
	user := p.Callback(userName, password)
	if user == nil {
		return nil, util.NewInvalidCredentialsError()
	}

	accessToken := p.createAccessToken(client, user)

	refreshToken := p.createRefreshToken(client, user, accessToken)

	return p.server.CreateResponse(accessToken, refreshToken), nil
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

func (p *PasswordGrant) createRefreshToken(client *model.Client, user *model.User, accessToken *model.AccessToken) *model.RefreshToken {
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
