package model

type AuthzCode struct {
	ID       int64
	Code     string
	ClientId string
}
