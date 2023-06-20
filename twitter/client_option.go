package twitter

import "net/http"

type ClientOption func(ClientConfig)

type ClientConfig struct {
	httpClient *http.Client
	userAgent  string
}

func HttpClient(httpClient *http.Client) ClientOption {
	return func(config ClientConfig) {
		config.httpClient = httpClient
	}
}

func UserAgent(userAgent string) ClientOption {
	return func(config ClientConfig) {
		config.userAgent = userAgent
	}
}
