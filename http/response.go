package http

type Response interface {
	RedirectUri(uri string)
}
