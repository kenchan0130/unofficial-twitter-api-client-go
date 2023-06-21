package twitter

import (
	"context"
	"testing"
)

func TestClient_GetUserLikingTweets(t *testing.T) {
	username, password, mfaSecret := setup(t)
	client, err := NewClient(username, password, MFASecret(mfaSecret))
	if err != nil {
		t.Fatalf("client.GetSession(): %v", err)
	}
	_, err = client.GetUserLikingTweets(context.Background(), "233812737", 20)
	if err != nil {
		t.Fatalf("client.GetUserLikingTweets(): %v", err)
	}
}
