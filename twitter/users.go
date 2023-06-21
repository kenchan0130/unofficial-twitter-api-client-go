package twitter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (c Client) GetUserByScreenName(ctx context.Context, screenName string) (User, error) {
	var result User
	variables, err := json.Marshal(struct {
		ScreenName               string `json:"screen_name"`
		WithSafetyModeUserFields bool   `json:"withSafetyModeUserFields"`
	}{
		ScreenName:               screenName,
		WithSafetyModeUserFields: true,
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	features, err := json.Marshal(struct {
		HiddenProfileLikesEnabled                                 bool `json:"hidden_profile_likes_enabled"`
		ResponsiveWebGraphqlExcludeDirectiveEnabled               bool `json:"responsive_web_graphql_exclude_directive_enabled"`
		VerifiedPhoneLabelEnabled                                 bool `json:"verified_phone_label_enabled"`
		SubscriptionsVerificationInfoVerifiedSinceEnabled         bool `json:"subscriptions_verification_info_verified_since_enabled"`
		HighlightsTweetsTabUiEnabled                              bool `json:"highlights_tweets_tab_ui_enabled"`
		CreatorSubscriptionsTweetPreviewApiEnabled                bool `json:"creator_subscriptions_tweet_preview_api_enabled"`
		ResponsiveWebGraphqlSkipUserProfileImageExtensionsEnabled bool `json:"responsive_web_graphql_skip_user_profile_image_extensions_enabled"`
		ResponsiveWebGraphqlTimelineNavigationEnabled             bool `json:"responsive_web_graphql_timeline_navigation_enabled"`
	}{
		HiddenProfileLikesEnabled:                                 false,
		ResponsiveWebGraphqlExcludeDirectiveEnabled:               true,
		VerifiedPhoneLabelEnabled:                                 false,
		SubscriptionsVerificationInfoVerifiedSinceEnabled:         true,
		HighlightsTweetsTabUiEnabled:                              true,
		CreatorSubscriptionsTweetPreviewApiEnabled:                true,
		ResponsiveWebGraphqlSkipUserProfileImageExtensionsEnabled: false,
		ResponsiveWebGraphqlTimelineNavigationEnabled:             true,
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://twitter.com/i/api/graphql/qRednkZG-rn1P6b48NINmQ/UserByScreenName", nil)
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	queryParameters := url.Values{
		"variables": {string(variables)},
		"features":  {string(features)},
	}
	req.URL.RawQuery = queryParameters.Encode()

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Csrf-Token", c.csrfToken)
	req.Header.Set("Cookie", fmt.Sprintf("auth_token=%s; ct0=%s", c.authToken, c.csrfToken))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return result, fmt.Errorf("request is invalid for %s, res.StatusCode: %d", req.URL.String(), res.StatusCode)
	}

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		Data struct {
			User struct {
				Result struct {
					Legacy struct {
						CreatedAt  string `json:"created_at"`
						Name       string `json:"name"`
						ScreenName string `json:"screen_name"`
					} `json:"legacy"`
					RestID string `json:"rest_id"`
				} `json:"result"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &data); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	createdAt, err := time.Parse(time.RubyDate, data.Data.User.Result.Legacy.CreatedAt)
	if err != nil {
		return result, fmt.Errorf("time.Parse(): %v", err)
	}

	result = User{
		CreatedAt: createdAt,
		ID:        data.Data.User.Result.RestID,
		Name:      data.Data.User.Result.Legacy.Name,
		Username:  data.Data.User.Result.Legacy.ScreenName,
	}

	return result, nil
}
