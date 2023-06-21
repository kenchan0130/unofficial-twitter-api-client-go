package twitter

import (
	"context"
	"testing"
)

func TestSessionClient_GetSession(t *testing.T) {
	username, password, mfaSecret := setup(t)
	client := NewSessionClient(MFASecret(mfaSecret))
	_, err := client.GetSession(context.Background(), username, password)
	if err != nil {
		t.Fatalf("client.GetSession(): %v", err)
	}
}
