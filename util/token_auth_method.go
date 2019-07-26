package util

type TokenAuthMethod int

const (
	Basic    TokenAuthMethod = 1
	Post     TokenAuthMethod = 2
	NonePKCE TokenAuthMethod = 3
)
