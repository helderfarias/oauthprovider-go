package oauthprovider

import (
	"github.com/helderfarias/oauthprovider-go/grant"
	"github.com/helderfarias/oauthprovider-go/http"
)

type AuthorizationServer struct {
	grants map[string]grant.GrantType
}

func NewAuthorizationServer() *AuthorizationServer {
	return &AuthorizationServer{
		grants: make(map[string]grant.GrantType),
	}
}

func (this *AuthorizationServer) hasGrantType(identified string) bool {
	return this.grants[identified].Identifier() != ""
}

func (this *AuthorizationServer) AddGrant(grantType grant.GrantType) {
	this.grants[grantType.Identifier()] = grantType
}

func (this *AuthorizationServer) IssueAccessToken(request http.Request) (string, error) {
	// 	String grantType = request.getParam(OAuthConstants.OAUTH_GRANT_TYPE);
	// if (OAuthUtils.isEmpty(grantType)) {
	// 	throw new InvalidRequestException(OAuthConstants.OAUTH_GRANT_TYPE);
	// }

	// if (!this.grantTypes.containsKey(grantType)) {
	//           throw new UnSupportedGrantTypeException(grantType);
	// }

	// OAuthMessage message = this.grantTypes.get(grantType).handleResponse(request);

	// return message.encode(new OAuthJson());
	return "message", nil
}
