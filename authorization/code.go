package authorization

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
)

type authorizationCode struct {
	server          server.Authorizable
	before          HandleResponseFunc
	after           HandleResponseFunc
	tokenAuthMethod util.TokenAuthMethod
}

type AuthorizationCodeOption func(*authorizationCode)

func NewAuthorizationCode(opts ...AuthorizationCodeOption) *authorizationCode {
	s := &authorizationCode{
		tokenAuthMethod: util.Post,
	}

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

func AuthorizationCodeTokenAuthMethd(arg util.TokenAuthMethod) AuthorizationCodeOption {
	return func(a *authorizationCode) {
		a.tokenAuthMethod = arg
	}
}

func (p *authorizationCode) SetServer(server server.Authorizable) {
	p.server = server
}

func (p *authorizationCode) Identifier() string {
	return util.OAUTH_CODE
}

func (p *authorizationCode) checkCodeChallenge(request http.Request) (model.AuthzCodeChallenge, error) {
	if p.tokenAuthMethod != util.NonePKCE {
		return model.AuthzCodeChallenge{}, nil
	}

	code := request.GetParam(util.OAUTH_CODE_CHALLENGE)
	if code == "" {
		code = request.GetParamUri(util.OAUTH_CODE_CHALLENGE)
	}

	method := request.GetParam(util.OAUTH_CODE_CHALLENGE_METHOD)
	if method == "" {
		method = request.GetParamUri(util.OAUTH_CODE_CHALLENGE_METHOD)
	}

	if code == "" {
		return model.AuthzCodeChallenge{}, util.NewInvalidRequestError(util.OAUTH_CODE_CHALLENGE)
	}

	if method == "" {
		return model.AuthzCodeChallenge{}, util.NewInvalidRequestError(util.OAUTH_CODE_CHALLENGE_METHOD)
	}

	if method != "S256" && method != "S512" {
		return model.AuthzCodeChallenge{}, util.NewInvalidCodeChallengeMethodError()
	}

	return model.AuthzCodeChallenge{Code: code, Method: method}, nil
}

func (p *authorizationCode) findAppCredencials(request http.Request) (string, string, error) {
	clientID, clientSecret := "", ""

	if data := request.GetAuthorizationBasic(); data != nil && len(data) >= 1 {
		clientID = data[0]
		clientSecret = data[1]
	}

	if clientID == "" {
		clientID = request.GetParam(util.OAUTH_CLIENT_ID)
		if clientID == "" {
			clientID = request.GetParamUri(util.OAUTH_CLIENT_ID)
		}
	}

	if clientSecret == "" {
		clientSecret = request.GetParam(util.OAUTH_CLIENT_SECRET)
		if clientSecret == "" {
			clientSecret = request.GetParamUri(util.OAUTH_CLIENT_SECRET)
		}
	}

	if clientID == "" {
		return "", "", util.NewInvalidRequestError(util.OAUTH_CLIENT_ID)
	}

	return clientID, clientSecret, nil
}

func (p *authorizationCode) findClientByTokenMethod(clientID string, clientSecret string, request http.Request) (*model.Client, error) {
	if p.tokenAuthMethod == util.Post {
		client := p.server.FindByCredencials(clientID, clientSecret)
		if client == nil {
			return nil, util.NewInvalidClientError()
		}
		return client, nil
	}

	client := p.server.FindClientById(clientID)
	if client == nil {
		return nil, util.NewInvalidClientError()
	}

	return client, nil
}

func (p *authorizationCode) HandleResponse(request http.Request) (string, error) {
	clientID, clientSecret, err := p.findAppCredencials(request)
	if err != nil {
		return "", err
	}

	client, err := p.findClientByTokenMethod(clientID, clientSecret, request)
	if err != nil {
		return "", err
	}

	if _, err := url.QueryUnescape(client.RedirectUri); err != nil || client.RedirectUri == "" {
		return "", util.NewInvalidRequestError("redirectURI")
	}

	_, err = p.server.CheckScope(request, client.Name)
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

	challenge, err := p.checkCodeChallenge(request)
	if err != nil {
		return "", err
	}

	err = p.server.StoreAuthzCode(&model.AuthzCode{
		Code:                authzCode,
		ClientId:            client.Name,
		CodeChallenge:       challenge.Code,
		CodeChallengeMethod: challenge.Method,
	})
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	responseURI := fmt.Sprintf("%s?code=%s", client.RedirectUri, authzCode)

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
