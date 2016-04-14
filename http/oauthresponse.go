package http

import (
	"net/http"
)

type OAuthResponse struct {
	HttpRequest  *http.Request
	HttpResponse http.ResponseWriter
}

func (o *OAuthResponse) RedirectUri(uri string) {
	http.Redirect(o.HttpResponse, o.HttpRequest, uri, http.StatusFound)
}
