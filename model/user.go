package model

type User struct {
	ID       int64
	Name     string
	Password string
	Roles    []string
	Extra    map[string]string
}
