package http

import (
	"net/http"
)

type OAuthReponse struct {
	HttpRequest  *http.Request
	HttpResponse http.ResponseWriter
}

func (o *OAuthReponse) RedirectUri(uri string) {
	http.Redirect(o.HttpResponse, o.HttpRequest, uri, http.StatusFound)
}
