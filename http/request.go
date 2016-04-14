package http

type Request interface {
	GetParamUri(key string) string

	GetParam(key string) string

	GetHeader(key string) string

	GetClientId() string

	GetClientSecret() string

	GetUserName() string

	GetPassword() string

	GetGrantType() string

	GetRefreshToken() string

	GetAuthorizationBasic() []string

	GetAuthorizationCode() string

	GetRevokeToken() string

	GetScopes() []string
}
