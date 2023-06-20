package twitter

import (
	"context"
	"testing"
)

func TestSessionClient_GetSession(t *testing.T) {
	username, password := setup(t)
	client := NewSessionClient()
	_, err := client.GetSession(context.Background(), username, password)
	if err != nil {
		t.Fatalf("client.GetSession(): %v", err)
	}
}
