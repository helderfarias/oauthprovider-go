package http

type Request interface {
	GetParam(key string) string

	GetHeader(authorization string) string

	GetClientId() string

	GetClientSecret() string

	GetUserName() string

	GetPassword() string

	GetGrantType() string

	GetRefreshToken() string

	GetAuthorizationBasic() []string

	GetRevokeToken() string
}
