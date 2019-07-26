package authorization

import (
	"fmt"
	"net/url"

	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	servertype "github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type AuthorizationToken struct {
	server servertype.Authorizable
}

func (this *AuthorizationToken) SetServer(server servertype.Authorizable) {
	this.server = server
}

func (this *AuthorizationToken) Identifier() string {
	return util.OAUTH_IMPLICIT_GRANT_TOKEN
}

func (p *AuthorizationToken) HandleResponse(request http.Request) (string, error) {
	clientID := request.GetParamUri(util.OAUTH_CLIENT_ID)
	if clientID == "" {
		return "", util.NewInvalidRequestError(util.OAUTH_CLIENT_ID)
	}

	redirectURI, err := url.QueryUnescape(request.GetParamUri(util.OAUTH_REDIRECT_URI))
	if err != nil || redirectURI == "" {
		return "", util.NewInvalidRequestError(util.OAUTH_REDIRECT_URI)
	}

	client := p.server.FindClientById(clientID)
	if client == nil {
		return "", util.NewInvalidClientError()
	}

	_, err = p.server.CheckScope(request, clientID)
	if err != nil {
		return "", util.NewInvalidScopeError()
	}

	accessToken, err := p.createAccessToken(client)
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	encode := p.server.CreateResponse(accessToken, nil).Message()

	responseURI := fmt.Sprintf("%s#access_token=%s&token_type=%s&expires_in=%d", redirectURI, encode.AccessToken, encode.TokenType, encode.ExpiresIn)

	state := request.GetParamUri(util.OAUTH_STATE)
	if state != "" {
		responseURI = fmt.Sprintf("%s&state=%s", responseURI, state)
	}

	return responseURI, nil
}

func (p *AuthorizationToken) createAccessToken(client *model.Client) (*model.AccessToken, error) {
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
