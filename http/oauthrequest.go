package http

type OAuthRequest struct {
}

func (o *OAuthRequest) GetParam(key string) string {
	return ""
}

func (o *OAuthRequest) GetHeader(authorization string) string {
	return ""
}

func (o *OAuthRequest) GetClientId() string {
	return ""
}

func (o *OAuthRequest) GetClientSecret() string {
	return ""
}

func (o *OAuthRequest) GetUserName() string {
	return ""
}

func (o *OAuthRequest) GetPassword() string {
	return ""
}

func (o *OAuthRequest) GetGrantType() string {
	return ""
}

func (o *OAuthRequest) GetRefreshToken() string {
	return ""
}

func (o *OAuthRequest) GetAuthorizationBasic() []string {
	return nil
}

func (o *OAuthRequest) GetRevokeToken() string {
	return ""
}
