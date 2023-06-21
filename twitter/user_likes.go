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

type tweetResultContent struct {
	EditControl tweetResultContentEditControl `json:"edit_control"`
	Legacy      tweetResultContentLegacy      `json:"legacy"`
}

type tweetResultContentLegacy struct {
	CreatedAt string `json:"created_at"`
	FullText  string `json:"full_text"`
	UserIDStr string `json:"user_id_str"`
	IDStr     string `json:"id_str"`
}

type tweetResultContentEditControl struct {
	EditTweetIDs []string `json:"edit_tweet_ids"`
}

func (c Client) GetUserLikingTweets(ctx context.Context, userID string, count int) ([]Tweet, error) {
	variables, err := json.Marshal(struct {
		UserID                 string `json:"userId"`
		Count                  int    `json:"count"`
		IncludePromotedContent bool   `json:"includePromotedContent"`
		WithClientEventToken   bool   `json:"withClientEventToken"`
		WithBirdwatchNotes     bool   `json:"withBirdwatchNotes"`
		WithVoice              bool   `json:"withVoice"`
		WithV2Timeline         bool   `json:"withV2Timeline"`
	}{
		UserID:                 userID,
		Count:                  count,
		IncludePromotedContent: false,
		WithClientEventToken:   false,
		WithBirdwatchNotes:     false,
		WithVoice:              true,
		WithV2Timeline:         true,
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal(): %v", err)
	}

	features, err := json.Marshal(struct {
		RwebListsTimelineRedesignEnabled                               bool `json:"rweb_lists_timeline_redesign_enabled"`
		ResponsiveWebGraphqlExcludeDirectiveEnabled                    bool `json:"responsive_web_graphql_exclude_directive_enabled"`
		VerifiedPhoneLabelEnabled                                      bool `json:"verified_phone_label_enabled"`
		CreatorSubscriptionsTweetPreviewApiEnabled                     bool `json:"creator_subscriptions_tweet_preview_api_enabled"`
		ResponsiveWebGraphqlTimelineNavigationEnabled                  bool `json:"responsive_web_graphql_timeline_navigation_enabled"`
		ResponsiveWebGraphqlSkipUserProfileImageExtensionsEnabled      bool `json:"responsive_web_graphql_skip_user_profile_image_extensions_enabled"`
		TweetypieUnmentionOptimizationEnabled                          bool `json:"tweetypie_unmention_optimization_enabled"`
		ResponsiveWebEditTweetApiEnabled                               bool `json:"responsive_web_edit_tweet_api_enabled"`
		GraphqlIsTranslatableRwebTweetIsTranslatableEnabled            bool `json:"graphql_is_translatable_rweb_tweet_is_translatable_enabled"`
		ViewCountsEverywhereApiEnabled                                 bool `json:"view_counts_everywhere_api_enabled"`
		LongformNotetweetsConsumptionEnabled                           bool `json:"longform_notetweets_consumption_enabled"`
		TweetAwardsWebTippingEnabled                                   bool `json:"tweet_awards_web_tipping_enabled"`
		FreedomOfSpeechNotReachFetchEnabled                            bool `json:"freedom_of_speech_not_reach_fetch_enabled"`
		StandardizedNudgesMisinfo                                      bool `json:"standardized_nudges_misinfo"`
		TweetWithVisibilityResultsPreferGqlLimitedActionsPolicyEnabled bool `json:"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled"`
		LongformNotetweetsRichTextReadEnabled                          bool `json:"longform_notetweets_rich_text_read_enabled"`
		LongformNotetweetsInlineMediaEnabled                           bool `json:"longform_notetweets_inline_media_enabled"`
		ResponsiveWebEnhanceCardsEnabled                               bool `json:"responsive_web_enhance_cards_enabled"`
	}{
		RwebListsTimelineRedesignEnabled:                               true,
		ResponsiveWebGraphqlExcludeDirectiveEnabled:                    true,
		VerifiedPhoneLabelEnabled:                                      false,
		CreatorSubscriptionsTweetPreviewApiEnabled:                     true,
		ResponsiveWebGraphqlTimelineNavigationEnabled:                  true,
		ResponsiveWebGraphqlSkipUserProfileImageExtensionsEnabled:      false,
		TweetypieUnmentionOptimizationEnabled:                          true,
		ResponsiveWebEditTweetApiEnabled:                               true,
		GraphqlIsTranslatableRwebTweetIsTranslatableEnabled:            true,
		ViewCountsEverywhereApiEnabled:                                 true,
		LongformNotetweetsConsumptionEnabled:                           true,
		TweetAwardsWebTippingEnabled:                                   false,
		FreedomOfSpeechNotReachFetchEnabled:                            true,
		StandardizedNudgesMisinfo:                                      true,
		TweetWithVisibilityResultsPreferGqlLimitedActionsPolicyEnabled: false,
		LongformNotetweetsRichTextReadEnabled:                          true,
		LongformNotetweetsInlineMediaEnabled:                           true,
		ResponsiveWebEnhanceCardsEnabled:                               false,
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://twitter.com/i/api/graphql/oMVoAYo_CFV8JSpP_e8HiA/Likes", nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext(): %v", err)
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
		return nil, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request is invalid for %s, res.StatusCode: %d", req.URL.String(), res.StatusCode)
	}

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		Data struct {
			User struct {
				Result struct {
					TimelineV2 struct {
						Timeline struct {
							Instructions []struct {
								Entries []struct {
									Content struct {
										ItemContent struct {
											TweetResults struct {
												Result struct {
													Tweet *struct {
														tweetResultContent
													} `json:"tweet"`
													tweetResultContent
												} `json:"result"`
											} `json:"tweet_results"`
										} `json:"itemContent"`
										EntryType string `json:"entryType"`
									} `json:"content"`
								} `json:"entries"`
							} `json:"instructions"`
						} `json:"timeline"`
					} `json:"timeline_v2"`
				} `json:"result"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	instructions := data.Data.User.Result.TimelineV2.Timeline.Instructions
	if len(instructions) != 1 {
		return nil, fmt.Errorf("no instructions, %s user may not exist, got %s", userID, string(resp))
	}

	var result []Tweet
	for _, entry := range instructions[0].Entries {
		if entry.Content.EntryType != "TimelineTimelineItem" {
			continue
		}

		editControl := entry.Content.ItemContent.TweetResults.Result.EditControl
		legacy := entry.Content.ItemContent.TweetResults.Result.Legacy
		if entry.Content.ItemContent.TweetResults.Result.Tweet != nil {
			editControl = entry.Content.ItemContent.TweetResults.Result.Tweet.EditControl
			legacy = entry.Content.ItemContent.TweetResults.Result.Tweet.Legacy
		}

		createdAt, err := time.Parse(time.RubyDate, legacy.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("time.Parse(): %v", err)
		}

		result = append(result, Tweet{
			AuthorID:            legacy.UserIDStr,
			CreatedAt:           createdAt,
			EditHistoryTweetIDs: editControl.EditTweetIDs,
			ID:                  legacy.IDStr,
			Text:                legacy.FullText,
		})
	}

	return result, nil
}
