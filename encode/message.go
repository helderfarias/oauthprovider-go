package encode

type Message interface {
	Encode() string
	Message() OAuthMessage
}
