package twitter

import "net/http"

type ClientOption func(ClientConfig)

type ClientConfig struct {
	httpClient *http.Client
	userAgent  string
	mfaSecret  string
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

func MFASecret(mfaSecret string) ClientOption {
	return func(config ClientConfig) {
		config.mfaSecret = mfaSecret
	}
}
