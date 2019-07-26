package authorization

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	servertype "github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type authorizationToken struct {
	server servertype.Authorizable
	before HandleResponseFunc
	after  HandleResponseFunc
}

type AuthorizationTokenOption func(*authorizationToken)

func NewAuthorizationToken(opts ...AuthorizationTokenOption) *authorizationToken {
	s := &authorizationToken{}

	for _, o := range opts {
		o(s)
	}

	return s
}

func AuthorizationTokenAfter(fn HandleResponseFunc) AuthorizationTokenOption {
	return func(a *authorizationToken) {
		a.after = fn
	}
}

func AuthorizationTokenBefore(fn HandleResponseFunc) AuthorizationTokenOption {
	return func(a *authorizationToken) {
		a.before = fn
	}
}

func (this *authorizationToken) SetServer(server servertype.Authorizable) {
	this.server = server
}

func (this *authorizationToken) Identifier() string {
	return util.OAUTH_IMPLICIT_GRANT_TOKEN
}

func (p *authorizationToken) HandleResponse(request http.Request) (string, error) {
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

	if p.before != nil {
		_, err = p.before(request)
		if err != nil {
			return "", err
		}
	}

	accessToken, err := p.createAccessToken(client)
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	encode := p.server.CreateResponse(accessToken, nil).Message()

	responseURI := fmt.Sprintf("%s#access_token=%s&token_type=%s&expires_in=%d", redirectURI, encode.AccessToken, encode.TokenType, encode.ExpiresIn)

	if state := strings.TrimSpace(request.GetParamUri(util.OAUTH_STATE)); state != "" {
		responseURI = fmt.Sprintf("%s&state=%s", responseURI, state)
	} else if state := strings.TrimSpace(request.GetParam(util.OAUTH_STATE)); state != "" {
		responseURI = fmt.Sprintf("%s&state=%s", responseURI, state)
	}

	if p.after != nil {
		afterResult, err := p.after(request, responseURI)
		if err != nil {
			return "", err
		}

		if afterResult != "" {
			responseURI = fmt.Sprintf("%s&%s", responseURI, afterResult)
		}
	}

	return responseURI, nil
}

func (p *authorizationToken) createAccessToken(client *model.Client) (*model.AccessToken, error) {
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
