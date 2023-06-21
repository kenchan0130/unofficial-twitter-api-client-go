package twitter

import "time"

type Tweet struct {
	AuthorID            string
	CreatedAt           time.Time
	EditHistoryTweetIDs []string
	ID                  string
	Text                string
}

type User struct {
	CreatedAt time.Time
	ID        string
	Name      string
	Username  string
}
