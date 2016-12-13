package authorization

import (
	"github.com/helderfarias/oauthprovider-go/grant"
	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server/type"
	"github.com/helderfarias/oauthprovider-go/util"
)

type AuthorizationToken struct {
	grantCode grant.AuthzCodeGrant
}

func (this *AuthorizationToken) SetServer(server servertype.Authorizable) {
	this.grantCode.SetServer(server)
}

func (this *AuthorizationToken) Identifier() string {
	return util.OAUTH_IMPLICIT_GRANT_TOKEN
}

func (this *AuthorizationToken) HandleResponse(request http.Request) (string, error) {
	encode, err := this.grantCode.HandleResponse(request)
	if err != nil {
		return "", err
	}

	return encode.Encode(), nil
}
