package twitter

import (
	"context"
	"testing"
)

func TestClient_GetUserLikingTweets(t *testing.T) {
	username, password, mfaSecret := setup(t)
	client, err := NewClient(username, password, MFASecret(mfaSecret))
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	tweets, err := client.GetUserLikingTweets(context.Background(), "965113717963735045", 20)
	if err != nil {
		t.Fatalf("client.GetUserLikingTweets(): %v", err)
	}

	if len(tweets) == 0 {
		t.Fatalf("len(tweets) == 0")
	}
}
