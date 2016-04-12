package scope

import (
	"errors"
	"fmt"

	"github.com/helderfarias/oauthprovider-go/http"
	"github.com/helderfarias/oauthprovider-go/server/type"
)

type ValidatorScope struct {
	Server servertype.Authorizable
}

func (this *ValidatorScope) Execute(request http.Request, clientId string) ([]string, error) {
	requestScope := request.GetScopes()

	if this.checkIfScopeParamValid(requestScope) {
		return []string{}, errors.New("Invalid request")
	}

	scopes := []string{}

	if len(requestScope) == 0 && this.Server.GetDefaultScope() != "" {
		scopes = append(scopes, this.Server.GetDefaultScope())
	}

	for _, rs := range requestScope {
		scopes = append(scopes, rs)
	}

	for _, scope := range scopes {
		if _, err := this.Server.FindScope(scope, clientId); err != nil {
			return []string{}, errors.New(fmt.Sprintf("The requested scope is invalid, unknown, or malformed. Check the '%s' scope.", scope))
		}
	}

	return scopes, nil
}

func (v *ValidatorScope) checkIfScopeParamValid(requestScope []string) bool {
	return v.Server.IsScopeRequired() &&
		v.Server.GetDefaultScope() == "" &&
		len(requestScope) == 0
}
