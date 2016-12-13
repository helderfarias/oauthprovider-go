package authorization

import (
	"fmt"
	"net/url"

	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/model"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/token"
	"github.com/helderfarias/oauthprovider-go/util"
)

type AuthorizationCode struct {
	server servertype.Authorizable
}

func (this *AuthorizationCode) SetServer(server servertype.Authorizable) {
	this.server = server
}

func (this *AuthorizationCode) Identifier() string {
	return util.OAUTH_CODE
}

func (this *AuthorizationCode) HandleResponse(request http.Request) (string, error) {
	authorization := request.GetAuthorizationBasic()
	if authorization == nil ||
		authorization[0] == "" ||
		authorization[1] == "" {
		return "", util.NewBadCredentialsError()
	}

	clientID := authorization[0]
	clientSecret := authorization[1]

	client := this.server.FindByCredencials(clientID, clientSecret)
	if client == nil {
		return "", util.NewInvalidClientError()
	}

	redirectURI := request.GetParam(util.OAUTH_REDIRECT_URI)
	_, err := url.QueryUnescape(redirectURI)
	if err != nil {
		return "", util.NewInvalidRequestError(redirectURI)
	}

	if redirectURI == "" {
		return "", util.NewUnauthorizedClientError()
	}

	_, err = this.server.CheckScope(request, clientID)
	if err != nil {
		return "", util.NewInvalidScopeError()
	}

	authorizeToken := &token.AuthorizeTokenGenerator{}
	authzCode, err := authorizeToken.GenerateCode()
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	err = this.server.StoreAuthzCode(&model.AuthzCode{Code: authzCode, ClientId: clientID})
	if err != nil {
		return "", util.NewOAuthRuntimeError()
	}

	responseURI := fmt.Sprintf("%s?code=%s", redirectURI, authzCode)

	state := request.GetParamUri(util.OAUTH_STATE)
	if state != "" {
		responseURI = fmt.Sprintf("%s&state=%s", responseURI, state)
	}

	return responseURI, nil
}
