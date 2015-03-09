package http

type Request interface {
	GetParam(key string) string
}
