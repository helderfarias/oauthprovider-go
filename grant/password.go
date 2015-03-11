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

func (p *PasswordGrant) HandleResponse(request http.Request) encode.Message {
	clientId := request.GetClientId()
	clientSecret := request.GetClientSecret()
	client := p.server.FindByCredencials(clientId, clientSecret)

	userName := request.GetUserName()
	password := request.GetPassword()
	user := p.callback.Find(userName, password)

	accessToken := p.createAccessToken(client, user)

	return p.server.CreateResponse(accessToken)
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
