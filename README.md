# unofficial-twitter-api-client-go

## Install

```sh
go get github.com/kenchan0130/unofficial-twitter-api-client-go
```

## Usage

```go
import (
    "github.com/kenchan0130/unofficial-twitter-api-client-go"
)

username := "Input your twitter username"
password := "Input your twitter password of user"
mfaSecret := "Input your twitter MFA Secret of user"

client, _ := NewClient(usernamae, password, MFASecret(mfaSecret))
tweets, _ := client.GetUserLikingTweets(context.Background(), "965113717963735045", 20)
```

## Testing

### Environment variables

| Name                 | Description                                       |
|----------------------|---------------------------------------------------|
| `TWITTER_USERNAME`   | Twitter username, same as screen name without `@` |
| `TWITTER_PASSWORD`   | Twitter password of user                          |
| `TWITTER_MFA_SECRET` | Twitter MFA Secret of user                        |
