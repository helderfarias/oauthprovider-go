package util

import (
	"encoding/json"
	"fmt"
)

type ErrorMessage struct {
	Message string `json:"error"`
}

type OAuthError struct {
	StatusCode int
	GrantType  string
	ErrorType  string
}

func NewInvalidAccessTokenError() *OAuthError {
	return &OAuthError{
		StatusCode: 400,
		GrantType:  "invalid_request",
		ErrorType:  "The access token is invalid.",
	}
}

func NewInvalidRequestError(grantType string) *OAuthError {
	message := fmt.Sprintf("The request is missing a required parameter,"+
		" includes an invalid parameter value, includes a parameter more than once, "+
		"or is otherwise malformed. Check the '%s' parameter.", grantType)

	return &OAuthError{
		StatusCode: 400,
		GrantType:  "invalid_request",
		ErrorType:  message,
	}
}

func NewUnSupportedGrantTypeError(grantType string) *OAuthError {
	message := fmt.Sprintf("The authorization grant type '%s' is not "+
		"supported by the authorization server.", grantType)

	return &OAuthError{
		StatusCode: 400,
		GrantType:  "unsupported_grant_type",
		ErrorType:  message,
	}
}

func (i *OAuthError) Error() string {
	bytes, err := json.Marshal(ErrorMessage{Message: i.ErrorType})

	if err != nil {
		return ""
	}

	return string(bytes)
}