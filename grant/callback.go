package grant

import (
	"github.com/helderfarias/oauthprovider-go/model"
)

type VerifyCredentialsCallback interface {
	Find(userName, password string) *model.User
}
