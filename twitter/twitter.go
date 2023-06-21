package twitter

import "time"

type Tweet struct {
	AuthorID            string
	CreatedAt           time.Time
	EditHistoryTweetIDs []string
	ID                  string
	Text                string
}
