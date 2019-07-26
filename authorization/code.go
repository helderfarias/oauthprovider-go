package authorization

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	servertype "github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
)

type authorizationCode struct {
	server servertype.Authorizable
	before HandleResponseFunc
	after  HandleResponseFunc
}

type AuthorizationCodeOption func(*authorizationCode)

func NewAuthorizationCode(opts ...AuthorizationCodeOption) *authorizationCode {
	s := &authorizationCode{}

	for _, o := range opts {
		o(s)
	}

	return s
}

func AuthorizationCodeAfter(fn HandleResponseFunc) AuthorizationCodeOption {
	return func(a *authorizationCode) {
		a.after = fn
	}
}

func AuthorizationCodeBefore(fn HandleResponseFunc) AuthorizationCodeOption {
	return func(a *authorizationCode) {
		a.before = fn
	}
}

func (p *authorizationCode) SetServer(server servertype.Authorizable) {
	p.server = server
}

func (p *authorizationCode) Identifier() string {
	return util.OAUTH_CODE
}

func (p *authorizationCode) HandleResponse(request http.Request) (string, error) {
	authorization := request.GetAuthorizationBasic()
	if authorization == nil ||
		authorization[0] == "" ||
		authorization[1] == "" {
		return "", util.NewBadCredentialsError()
	}

	clientID := authorization[0]
	clientSecret := authorization[1]

	client := p.server.FindByCredencials(clientID, clientSecret)
	if client == nil {
		return "", util.NewInvalidClientError()
	}

	redirectURI := client.RedirectUri
	_, err := url.QueryUnescape(redirectURI)
	if err != nil || redirectURI == "" {
		return "", util.NewInvalidRequestError(redirectURI)
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

	authorizeToken := &token.AuthorizeTokenGenerator{}
	authzCode, err := authorizeToken.GenerateCode()
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	err = p.server.StoreAuthzCode(&model.AuthzCode{Code: authzCode, ClientId: clientID})
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	responseURI := fmt.Sprintf("%s?code=%s", redirectURI, authzCode)

	if state := strings.TrimSpace(request.GetParamUri(util.OAUTH_STATE)); state != "" {
		responseURI = fmt.Sprintf("%s&state=%s", responseURI, state)
	} else if state := strings.TrimSpace(request.GetParam(util.OAUTH_STATE)); state != "" {
		responseURI = fmt.Sprintf("%s&state=%s", responseURI, state)
	}

	if p.after != nil {
		result, err := p.after(request, responseURI)
		if err != nil {
			return "", err
		}

		if result != "" {
			responseURI = fmt.Sprintf("%s&%s", responseURI, result)
		}
	}

	return responseURI, nil
}
