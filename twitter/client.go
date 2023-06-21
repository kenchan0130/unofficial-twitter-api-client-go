package twitter

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"net/http"
)

type Client struct {
	bearerToken string
	httpClient  *http.Client
	userAgent   string
	csrfToken   string
	authToken   string
}

func NewClient(username string, password string, options ...ClientOption) (Client, error) {
	config := newDefaultRetryConfig()

	for _, option := range options {
		option(config)
	}
	sessionClient := NewSessionClient(options...)
	session, err := sessionClient.GetSession(context.Background(), username, password)
	if err != nil {
		return Client{}, fmt.Errorf("SessionClient.GetSession(): %w", err)
	}

	client := Client{
		// This token is owned by Twitter app
		bearerToken: "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
		httpClient:  config.httpClient,
		userAgent:   config.userAgent,
		csrfToken:   session.CSRFToken,
		authToken:   session.AuthToken,
	}

	return client, nil
}

func newDefaultRetryConfig() *ClientConfig {
	return &ClientConfig{
		httpClient: retryablehttp.NewClient().StandardClient(),
		userAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	}
}
