package twitter

import (
	"os"
	"testing"
)

func setup(t *testing.T) (string, string, string) {
	username := os.Getenv("TWITTER_USERNAME")
	if username == "" {
		t.Fatalf("TWITTER_USERNAME is required")
	}
	password := os.Getenv("TWITTER_PASSWORD")
	if password == "" {
		t.Fatalf("TWITTER_PASSWORD is required")
	}
	mfaSecret := os.Getenv("TWITTER_MFA_SECRET")
	if password == "" {
		t.Fatalf("TWITTER_MFA_SECRET is required")
	}

	return username, password, mfaSecret
}
