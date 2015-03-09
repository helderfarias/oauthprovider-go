package server

import (
	"github.com/helderfarias/oauthprovider-go/grant"
	"github.com/helderfarias/oauthprovider-go/http"
)

type Authorizable interface {
	AddGrant(grantType grant.GrantType)
	IssueAccessToken(request http.Request) (string, error)
}
