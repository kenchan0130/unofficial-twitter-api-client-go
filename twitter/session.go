package twitter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pquerna/otp/totp"
	"github.com/samber/lo"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SessionClient struct {
	bearerToken string
	httpClient  *http.Client
	userAgent   string
	mfaSecret   string
}

func NewSessionClient(options ...ClientOption) SessionClient {
	config := newDefaultRetryConfig()

	for _, option := range options {
		option(config)
	}
	client := SessionClient{
		// This token is owned by Twitter app
		bearerToken: "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
		httpClient:  config.httpClient,
		userAgent:   config.userAgent,
	}

	return client
}

type SubtaskID string

const (
	SubtaskIDAccountDuplicationCheck              SubtaskID = "AccountDuplicationCheck"
	SubtaskIDLoginAcid                            SubtaskID = "LoginAcid"
	SubtaskIDLoginEnterUserIdentifierSSO          SubtaskID = "LoginEnterUserIdentifierSSO"
	SubtaskIDLoginEnterAlternateIdentifierSubtask SubtaskID = "LoginEnterAlternateIdentifierSubtask"
	SubtaskIDLoginEnterPassword                   SubtaskID = "LoginEnterPassword"
	SubtaskIDLoginJsInstrumentationSubtask        SubtaskID = "LoginJsInstrumentationSubtask"
	SubtaskIDLoginTwoFactorAuthChallenge          SubtaskID = "LoginTwoFactorAuthChallenge"
	SubtaskIDLoginSuccessSubtask                  SubtaskID = "LoginSuccessSubtask"
	SubtaskIDEnterIdGoogleSSOSubtask              SubtaskID = "EnterIdGoogleSSOSubtask"
	SubtaskIDEnterIdAppleSSOSubtask               SubtaskID = "EnterIdAppleSSOSubtask"
	SubtaskIDPwrJsInstrumentationSubtask          SubtaskID = "PwrJsInstrumentationSubtask"
	SubtaskIDPasswordResetBegin                   SubtaskID = "PasswordResetBegin"
	SubtaskIDPasswordResetChooseChallenge         SubtaskID = "PasswordResetChooseChallenge"
	SubtaskIDPasswordResetConfirmChallenge        SubtaskID = "PasswordResetConfirmChallenge"
	SubtaskIDPasswordResetNewPassword             SubtaskID = "PasswordResetNewPassword"
	SubtaskIDPasswordResetSurvey                  SubtaskID = "PasswordResetSurvey"
	SubtaskIDRedirectToPasswordReset              SubtaskID = "RedirectToPasswordReset"
	SubtaskIDPwrKnowledgeChallenge                SubtaskID = "PwrKnowledgeChallenge"
	SubtaskIDSuccessExit                          SubtaskID = "SuccessExit"
	SubtaskIDLoginOpenHomeTimeline                SubtaskID = "LoginOpenHomeTimeline"
	SubtaskIDLoginTwoFactorAuthChooseMethod       SubtaskID = "LoginTwoFactorAuthChooseMethod"
	SubtaskIDLoginSecurityKeyNotSupportedCta      SubtaskID = "login_security_key_not_supported_cta"
)

type Session struct {
	CSRFToken string
	AuthToken string
}

type initLoginFlowRequest struct {
	InputFlowData   initLoginFlowRequestInputFlowData `json:"input_flow_data"`
	SubtaskVersions map[string]int                    `json:"subtask_versions"`
}

type initLoginFlowRequestInputFlowData struct {
	FlowContext initLoginFlowDataFlowContext `json:"flow_context"`
}
type initLoginFlowDataFlowContext struct {
	DebugOverrides map[string]interface{}                    `json:"debug_overrides"`
	StartLocation  initLoginFlowDataFlowContextStartLocation `json:"start_location"`
}

type initLoginFlowDataFlowContextStartLocation struct {
	Location string `json:"location"`
}

type loginFlowSession struct {
	Att         string
	FlowToken   string
	NextStepIDs []SubtaskID
	Session     Session
}

func (s loginFlowSession) IsFailedFlow() bool {
	return s.FlowToken == "" && s.Session.AuthToken == ""
}

func (s loginFlowSession) HasSession() bool {
	return s.Session.AuthToken != ""
}

type loginFlowRequest struct {
	FlowToken     string                         `json:"flow_token"`
	SubtaskInputs []loginFlowRequestSubtaskInput `json:"subtask_inputs"`
}

type loginFlowRequestSubtaskInput struct {
	SubtaskID            SubtaskID                                         `json:"subtask_id"`
	EnterPassword        *loginFlowRequestSubtaskInputEnterPassword        `json:"enter_password"`
	EnterText            *loginFlowRequestSubtaskInputEnterText            `json:"enter_text"`
	SettingsList         *loginFlowRequestSubtaskInputSettingsList         `json:"settings_list"`
	CheckLoggedInAccount *loginFlowRequestSubtaskInputCheckLoggedInAccount `json:"check_logged_in_account"`
	JSInstrumentation    *loginFlowRequestSubtaskInputJSInstrumentation    `json:"js_instrumentation"`
}

type loginFlowRequestSubtaskInputJSInstrumentation struct {
	Response string `json:"response"`
	Link     string `json:"link"`
}

type loginFlowRequestSubtaskInputCheckLoggedInAccount struct {
	Link string `json:"link"`
}

type loginFlowRequestSubtaskInputSettingsList struct {
	SettingResponses []loginFlowRequestSubtaskInputSettingsListSettingResponse `json:"setting_responses"`
	Link             string                                                    `json:"link"`
}

type loginFlowRequestSubtaskInputSettingsListSettingResponse struct {
	Key          string                                                              `json:"key"`
	ResponseData loginFlowRequestSubtaskInputSettingsListSettingResponseResponseData `json:"response_data"`
}

type loginFlowRequestSubtaskInputSettingsListSettingResponseResponseData struct {
	TextData loginFlowRequestSubtaskInputSettingsListSettingResponseResponseDataTextData `json:"text_data"`
}

type loginFlowRequestSubtaskInputSettingsListSettingResponseResponseDataTextData struct {
	Result string `json:"result"`
}

type loginFlowRequestSubtaskInputEnterPassword struct {
	Password string `json:"password"`
	Link     string `json:"link"`
}

type loginFlowRequestSubtaskInputEnterText struct {
	Text string `json:"text"`
	Link string `json:"link"`
}

type taskResponse struct {
	FlowToken string `json:"flow_token"`
	Subtasks  []struct {
		SubtaskID string `json:"subtask_id"`
	} `json:"subtasks"`
}

func (c SessionClient) GetSession(ctx context.Context, username string, password string) (Session, error) {
	var result Session
	guestToken, err := c.getGuestToken(ctx)
	if err != nil {
		return result, fmt.Errorf("Client.getGuestToken(): %v", err)
	}

	flowSession, err := c.getAuthTokenInitTask(ctx, guestToken)
	if err != nil {
		return result, fmt.Errorf("Client.getAuthTokenInitTask(): %v", err)
	}

	flowSession, err = c.getAuthTokenLoginJsInstrumentationSubtask(ctx, guestToken, flowSession)
	if err != nil {
		return result, fmt.Errorf("Client.getAuthTokenLoginJsInstrumentationSubtask(): %v", err)
	}

	time.Sleep(1 * time.Second)

	flowSession, err = c.getAuthTokenLoginEnterUserIdentifierTask(ctx, guestToken, flowSession, username)
	if err != nil {
		return result, fmt.Errorf("Client.getAuthTokenLoginEnterUserIdentifierTask(): %v", err)
	}

	if lo.Contains(flowSession.NextStepIDs, SubtaskIDLoginEnterAlternateIdentifierSubtask) {
		time.Sleep(1 * time.Second)

		flowSession, err = c.getAuthTokenLoginEnterAlternateIdentifierSubtask(ctx, guestToken, flowSession, username)
		if err != nil {
			return result, fmt.Errorf("Client.getAuthTokenLoginEnterAlternateIdentifierSubtask(): %v", err)
		}
	}

	time.Sleep(1 * time.Second)

	flowSession, err = c.getAuthTokenLoginEnterPasswordTask(ctx, guestToken, flowSession, password)
	if err != nil {
		return result, fmt.Errorf("Client.getAuthTokenLoginEnterPasswordTask(): %v", err)
	}

	if flowSession.HasSession() {
		newCSRFToken, err := c.getCSRFToken(ctx, guestToken, flowSession.Session)
		if err != nil {
			return result, fmt.Errorf("Client.getCSRFToken(): %v", err)
		}
		result = flowSession.Session
		result.CSRFToken = newCSRFToken

		return result, nil
	}

	time.Sleep(1 * time.Second)

	flowSession, err = c.getAuthTokenAccountDuplicationCheckTask(ctx, guestToken, flowSession)
	if err != nil {
		return result, fmt.Errorf("Client.getAuthTokenAccountDuplicationCheckTask(): %v", err)
	}

	if flowSession.HasSession() {
		newCSRFToken, err := c.getCSRFToken(ctx, guestToken, flowSession.Session)
		if err != nil {
			return result, fmt.Errorf("Client.getCSRFToken(): %v", err)
		}
		result = flowSession.Session
		result.CSRFToken = newCSRFToken

		return result, nil
	}

	if !lo.Contains(flowSession.NextStepIDs, SubtaskIDLoginTwoFactorAuthChallenge) {
		return result, fmt.Errorf("unsupported subtasks %s", strings.Join(lo.Map(flowSession.NextStepIDs, func(v SubtaskID, _ int) string { return string(v) }), ", "))
	}

	code, err := totp.GenerateCode(c.mfaSecret, time.Now().UTC())
	if err != nil {
		return result, fmt.Errorf("totp.GenerateCode(): %v", err)
	}

	time.Sleep(1 * time.Second)

	flowSession, err = c.getAuthTokenLoginTwoFactorAuthChallengeTask(ctx, guestToken, flowSession, code)
	if err != nil {
		return result, fmt.Errorf("Client.getAuthTokenLoginTwoFactorAuthChallengeTask(): %v", err)
	}

	if !flowSession.HasSession() {
		return result, fmt.Errorf("no session found, API specificaton may have changed")
	}

	newCSRFToken, err := c.getCSRFToken(ctx, guestToken, flowSession.Session)
	if err != nil {
		return result, fmt.Errorf("Client.getCSRFToken(): %v", err)
	}
	result = flowSession.Session
	result.CSRFToken = newCSRFToken

	return result, nil
}

func (c SessionClient) getGuestToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/guest/activate.json", nil)
	if err != nil {
		return "", fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Client.httpClient.Do(): %v", err)
	}

	defer res.Body.Close()
	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		GuestToken string `json:"guest_token"`
	}
	if err := json.Unmarshal(resp, &data); err != nil {
		return "", fmt.Errorf("json.Unmarshal(): %v", err)
	}

	if data.GuestToken == "" {
		return "", fmt.Errorf("the 'guest_token' is empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}

	return data.GuestToken, nil
}

func (c SessionClient) getAuthTokenInitTask(ctx context.Context, guestToken string) (loginFlowSession, error) {
	var result loginFlowSession
	initLoginFlowRequest, err := json.Marshal(initLoginFlowRequest{
		InputFlowData: initLoginFlowRequestInputFlowData{
			FlowContext: initLoginFlowDataFlowContext{
				DebugOverrides: map[string]interface{}{},
				StartLocation: initLoginFlowDataFlowContextStartLocation{
					Location: "manual_link",
				},
			},
		},
		SubtaskVersions: map[string]int{},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json?flow_name=login", bytes.NewBuffer(initLoginFlowRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	if taskRes.FlowToken == "" {
		return result, fmt.Errorf("the 'flow_token' is empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	result.FlowToken = taskRes.FlowToken

	if len(taskRes.Subtasks) == 0 {
		return result, fmt.Errorf("the 'subtasks' is blank. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	for _, cookie := range res.Cookies() {
		if cookie != nil && cookie.Name == "att" {
			result.Att = cookie.Value
		}
	}
	if result.Att == "" {
		return result, fmt.Errorf("the 'att' is empty at cookie. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}

	return result, nil
}

func (c SessionClient) getAuthTokenLoginJsInstrumentationSubtask(ctx context.Context, guestToken string, session loginFlowSession) (loginFlowSession, error) {
	var result loginFlowSession
	taskRequest, err := json.Marshal(loginFlowRequest{
		FlowToken: session.FlowToken,
		SubtaskInputs: []loginFlowRequestSubtaskInput{
			{
				SubtaskID: SubtaskIDLoginJsInstrumentationSubtask,
				JSInstrumentation: &loginFlowRequestSubtaskInputJSInstrumentation{
					Response: "{}",
					Link:     "next_link",
				},
			},
		},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json", bytes.NewBuffer(taskRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("cookie", fmt.Sprintf("att=%s", session.Att))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	if taskRes.FlowToken == "" {
		return result, fmt.Errorf("the 'flow_token' is empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	result.FlowToken = taskRes.FlowToken
	result.Att = session.Att

	if len(taskRes.Subtasks) == 0 {
		return result, fmt.Errorf("the 'subtasks' is blank. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	return result, nil
}

func (c SessionClient) getAuthTokenLoginEnterUserIdentifierTask(ctx context.Context, guestToken string, session loginFlowSession, username string) (loginFlowSession, error) {
	var result loginFlowSession
	taskRequest, err := json.Marshal(loginFlowRequest{
		FlowToken: session.FlowToken,
		SubtaskInputs: []loginFlowRequestSubtaskInput{
			{
				SubtaskID: SubtaskIDLoginEnterUserIdentifierSSO,
				SettingsList: &loginFlowRequestSubtaskInputSettingsList{
					SettingResponses: []loginFlowRequestSubtaskInputSettingsListSettingResponse{
						{
							Key: "user_identifier",
							ResponseData: loginFlowRequestSubtaskInputSettingsListSettingResponseResponseData{
								TextData: loginFlowRequestSubtaskInputSettingsListSettingResponseResponseDataTextData{
									Result: username,
								},
							},
						},
					},
					Link: "next_link",
				},
			},
		},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json", bytes.NewBuffer(taskRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("cookie", fmt.Sprintf("att=%s", session.Att))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	if taskRes.FlowToken == "" {
		return result, fmt.Errorf("the 'flow_token' is empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	result.FlowToken = taskRes.FlowToken
	result.Att = session.Att

	if len(taskRes.Subtasks) == 0 {
		return result, fmt.Errorf("the 'subtasks' is blank. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	return result, nil
}

func (c SessionClient) getAuthTokenLoginEnterPasswordTask(ctx context.Context, guestToken string, session loginFlowSession, password string) (loginFlowSession, error) {
	var result loginFlowSession
	taskRequest, err := json.Marshal(loginFlowRequest{
		FlowToken: session.FlowToken,
		SubtaskInputs: []loginFlowRequestSubtaskInput{
			{
				SubtaskID: SubtaskIDLoginEnterPassword,
				EnterPassword: &loginFlowRequestSubtaskInputEnterPassword{
					Password: password,
					Link:     "next_link",
				},
			},
		},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json", bytes.NewBuffer(taskRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("cookie", fmt.Sprintf("att=%s", session.Att))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	result.FlowToken = taskRes.FlowToken
	result.Att = session.Att

	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == "auth_token" {
			result.Session.AuthToken = cookie.Value
		}
		if cookie.Name == "ct0" {
			result.Session.CSRFToken = cookie.Value
		}
	}

	if result.IsFailedFlow() {
		return result, fmt.Errorf("some values may be empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}

	return result, nil
}

func (c SessionClient) getAuthTokenAccountDuplicationCheckTask(ctx context.Context, guestToken string, session loginFlowSession) (loginFlowSession, error) {
	var result loginFlowSession
	taskRequest, err := json.Marshal(loginFlowRequest{
		FlowToken: session.FlowToken,
		SubtaskInputs: []loginFlowRequestSubtaskInput{
			{
				SubtaskID: SubtaskIDAccountDuplicationCheck,
				CheckLoggedInAccount: &loginFlowRequestSubtaskInputCheckLoggedInAccount{
					Link: "AccountDuplicationCheck_false",
				},
			},
		},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json", bytes.NewBuffer(taskRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("cookie", fmt.Sprintf("att=%s", session.Att))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	result.FlowToken = taskRes.FlowToken
	result.Att = session.Att

	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == "auth_token" {
			result.Session.AuthToken = cookie.Value
		}
		if cookie.Name == "ct0" {
			result.Session.CSRFToken = cookie.Value
		}
	}

	if result.IsFailedFlow() {
		return result, fmt.Errorf("some values may be empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}

	return result, nil
}

func (c SessionClient) getAuthTokenLoginEnterAlternateIdentifierSubtask(ctx context.Context, guestToken string, session loginFlowSession, username string) (loginFlowSession, error) {
	var result loginFlowSession
	taskRequest, err := json.Marshal(loginFlowRequest{
		FlowToken: session.FlowToken,
		SubtaskInputs: []loginFlowRequestSubtaskInput{
			{
				SubtaskID: SubtaskIDLoginEnterAlternateIdentifierSubtask,
				EnterText: &loginFlowRequestSubtaskInputEnterText{
					Text: username,
					Link: "next_link",
				},
			},
		},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json", bytes.NewBuffer(taskRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("cookie", fmt.Sprintf("att=%s", session.Att))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	if taskRes.FlowToken == "" {
		return result, fmt.Errorf("the 'flow_token' is empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}
	result.FlowToken = taskRes.FlowToken
	result.Att = session.Att

	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	return result, nil
}

func (c SessionClient) getAuthTokenLoginTwoFactorAuthChallengeTask(ctx context.Context, guestToken string, session loginFlowSession, code string) (loginFlowSession, error) {
	var result loginFlowSession
	taskRequest, err := json.Marshal(loginFlowRequest{
		FlowToken: session.FlowToken,
		SubtaskInputs: []loginFlowRequestSubtaskInput{
			{
				SubtaskID: SubtaskIDLoginTwoFactorAuthChallenge,
				EnterText: &loginFlowRequestSubtaskInputEnterText{
					Text: code,
					Link: "next_link",
				},
			},
		},
	})
	if err != nil {
		return result, fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/1.1/onboarding/task.json", bytes.NewBuffer(taskRequest))
	if err != nil {
		return result, fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("cookie", fmt.Sprintf("att=%s", session.Att))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var taskRes taskResponse
	if err := json.Unmarshal(resp, &taskRes); err != nil {
		return result, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	result.FlowToken = taskRes.FlowToken
	result.Att = session.Att

	for _, subtask := range taskRes.Subtasks {
		id, err := DecodeSubtaskID(subtask.SubtaskID)
		if err != nil {
			return result, fmt.Errorf("DecodeSubtaskID(): %v", err)
		}
		result.NextStepIDs = append(result.NextStepIDs, id)
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == "auth_token" {
			result.Session.AuthToken = cookie.Value
		}
		if cookie.Name == "ct0" {
			result.Session.CSRFToken = cookie.Value
		}
	}

	if result.IsFailedFlow() {
		return result, fmt.Errorf("some values may be empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}

	return result, nil
}

func (c SessionClient) getCSRFToken(ctx context.Context, guestToken string, session Session) (string, error) {
	variables, err := json.Marshal(struct {
		WithCommunitiesMemberships bool `json:"withCommunitiesMemberships"`
		WithCommunitiesCreation    bool `json:"withCommunitiesCreation"`
		WithSuperFollowsUserFields bool `json:"withSuperFollowsUserFields"`
	}{
		WithCommunitiesMemberships: true,
		WithCommunitiesCreation:    true,
		WithSuperFollowsUserFields: true,
	})
	if err != nil {
		return "", fmt.Errorf("json.Marshal(): %v", err)
	}

	features, err := json.Marshal(struct {
		ResponsiveWebGraphqlExcludeDirectiveEnabled               bool `json:"responsive_web_graphql_exclude_directive_enabled"`
		ResponsiveWebGraphqlSkipUserProfileImageExtensionsEnabled bool `json:"responsive_web_graphql_skip_user_profile_image_extensions_enabled"`
		ResponsiveWebGraphqlTimelineNavigationEnabled             bool `json:"responsive_web_graphql_timeline_navigation_enabled"`
		VerifiedPhoneLabelEnabled                                 bool `json:"verified_phone_label_enabled"`
	}{
		ResponsiveWebGraphqlExcludeDirectiveEnabled:               true,
		ResponsiveWebGraphqlSkipUserProfileImageExtensionsEnabled: false,
		ResponsiveWebGraphqlTimelineNavigationEnabled:             true,
		VerifiedPhoneLabelEnabled:                                 false,
	})
	if err != nil {
		return "", fmt.Errorf("json.Marshal(): %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://twitter.com/i/api/graphql/k3027HdkVqbuDPpdoniLKA/Viewer", nil)
	if err != nil {
		return "", fmt.Errorf("http.NewRequestWithContext(): %v", err)
	}

	queryParameters := url.Values{
		"variables": {string(variables)},
		"features":  {string(features)},
	}
	req.URL.RawQuery = queryParameters.Encode()

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.bearerToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-guest-token", guestToken)
	req.Header.Set("X-Csrf-Token", session.CSRFToken)
	req.Header.Set("cookie", fmt.Sprintf("auth_token=%s; ct0=%s", session.AuthToken, session.CSRFToken))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Client.httpClient.Do(): %v", err)
	}
	defer res.Body.Close()

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("io.ReadAll(): %v", err)
	}

	var result string
	for _, cookie := range res.Cookies() {
		if cookie.Name == "ct0" {
			result = cookie.Value
		}
	}

	if result == "" {
		return result, fmt.Errorf("the 'ct0' is empty. API specifications may have changed, url: %s status: %d body: %s", req.URL.String(), res.StatusCode, string(resp))
	}

	return result, nil
}

func DecodeSubtaskID(s string) (SubtaskID, error) {
	switch s {
	case string(SubtaskIDLoginJsInstrumentationSubtask):
		return SubtaskIDLoginJsInstrumentationSubtask, nil
	case string(SubtaskIDLoginEnterUserIdentifierSSO):
		return SubtaskIDLoginEnterUserIdentifierSSO, nil
	case string(SubtaskIDAccountDuplicationCheck):
		return SubtaskIDAccountDuplicationCheck, nil
	case string(SubtaskIDLoginEnterAlternateIdentifierSubtask):
		return SubtaskIDLoginEnterAlternateIdentifierSubtask, nil
	case string(SubtaskIDLoginEnterPassword):
		return SubtaskIDLoginEnterPassword, nil
	case string(SubtaskIDLoginTwoFactorAuthChallenge):
		return SubtaskIDLoginTwoFactorAuthChallenge, nil
	case string(SubtaskIDLoginAcid):
		return SubtaskIDLoginAcid, nil
	case string(SubtaskIDPwrJsInstrumentationSubtask):
		return SubtaskIDPwrJsInstrumentationSubtask, nil
	case string(SubtaskIDPasswordResetBegin):
		return SubtaskIDPasswordResetBegin, nil
	case string(SubtaskIDPasswordResetChooseChallenge):
		return SubtaskIDPasswordResetChooseChallenge, nil
	case string(SubtaskIDPwrKnowledgeChallenge):
		return SubtaskIDPwrKnowledgeChallenge, nil
	case string(SubtaskIDPasswordResetConfirmChallenge):
		return SubtaskIDPasswordResetConfirmChallenge, nil
	case string(SubtaskIDPasswordResetNewPassword):
		return SubtaskIDPasswordResetNewPassword, nil
	case string(SubtaskIDPasswordResetSurvey):
		return SubtaskIDPasswordResetSurvey, nil
	case string(SubtaskIDEnterIdGoogleSSOSubtask):
		return SubtaskIDEnterIdGoogleSSOSubtask, nil
	case string(SubtaskIDEnterIdAppleSSOSubtask):
		return SubtaskIDEnterIdAppleSSOSubtask, nil
	case string(SubtaskIDRedirectToPasswordReset):
		return SubtaskIDRedirectToPasswordReset, nil
	case string(SubtaskIDLoginSuccessSubtask):
		return SubtaskIDLoginSuccessSubtask, nil
	case string(SubtaskIDSuccessExit):
		return SubtaskIDSuccessExit, nil
	case string(SubtaskIDLoginOpenHomeTimeline):
		return SubtaskIDLoginOpenHomeTimeline, nil
	case string(SubtaskIDLoginTwoFactorAuthChooseMethod):
		return SubtaskIDLoginTwoFactorAuthChooseMethod, nil
	case string(SubtaskIDLoginSecurityKeyNotSupportedCta):
		return SubtaskIDLoginSecurityKeyNotSupportedCta, nil
	default:
		return "", fmt.Errorf("invalid SubtaskID: %s", s)
	}
}
