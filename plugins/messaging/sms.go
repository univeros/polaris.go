package messaging

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxProviderBody bounds what is read of a provider's answer.
const maxProviderBody = 1 << 20

// HTTPSMS sends each SMS as one HTTP request to any provider's API: Request builds it, a 2xx answer
// is a delivery, anything else (or a transport error) an error naming the status. ProviderID, when
// set, reads the provider's message id from a 2xx body.
type HTTPSMS struct {
	ChannelName string       // "" means "http_sms"
	Client      *http.Client // nil means http.DefaultClient
	Request     func(ctx context.Context, m Message) (*http.Request, error)
	ProviderID  func(body []byte) string
}

// Name implements Channel.
func (h *HTTPSMS) Name() string {
	if h.ChannelName == "" {
		return "http_sms"
	}
	return h.ChannelName
}

// Supports implements Channel: SMS only.
func (*HTTPSMS) Supports(kind string) bool { return kind == KindSMS }

// Send implements Channel.
func (h *HTTPSMS) Send(ctx context.Context, m Message) (string, error) {
	if h.Request == nil {
		return "", errors.New("http_sms: Request is not set")
	}
	req, err := h.Request(ctx, m)
	if err != nil {
		return "", fmt.Errorf("%s: %w", h.Name(), err)
	}
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", h.Name(), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s answered HTTP %d", h.Name(), resp.StatusCode)
	}
	if h.ProviderID == nil {
		return "", nil
	}
	return h.ProviderID(body), nil
}

// Twilio sends SMS through Twilio's Messages API (POST /2010-04-01/Accounts/{sid}/Messages.json,
// basic auth, form body); the provider id is the message's sid.
type Twilio struct {
	AccountSID string
	AuthToken  string
	From       string       // a Twilio number in E.164 form
	BaseURL    string       // "" means https://api.twilio.com
	Client     *http.Client // nil means http.DefaultClient
}

// Name implements Channel.
func (*Twilio) Name() string { return "twilio" }

// Supports implements Channel: SMS only.
func (*Twilio) Supports(kind string) bool { return kind == KindSMS }

// Send implements Channel.
func (t *Twilio) Send(ctx context.Context, m Message) (string, error) {
	base := t.BaseURL
	if base == "" {
		base = "https://api.twilio.com"
	}
	h := HTTPSMS{ChannelName: t.Name(), Client: t.Client,
		Request: func(ctx context.Context, m Message) (*http.Request, error) {
			form := url.Values{"To": {m.To}, "From": {t.From}, "Body": {m.Text}}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				fmt.Sprintf("%s/2010-04-01/Accounts/%s/Messages.json", base, url.PathEscape(t.AccountSID)), strings.NewReader(form.Encode()))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(t.AccountSID+":"+t.AuthToken)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req, nil
		},
		ProviderID: func(body []byte) string {
			var r struct{ Sid string }
			_ = json.Unmarshal(body, &r)
			return r.Sid
		}}
	return h.Send(ctx, m)
}

// Vonage sends SMS through Vonage's SMS API (POST https://rest.nexmo.com/sms/json, JSON body); the
// provider id is the first message's id.
type Vonage struct {
	APIKey    string
	APISecret string
	From      string       // a number or an alphanumeric sender id
	Endpoint  string       // "" means https://rest.nexmo.com/sms/json
	Client    *http.Client // nil means http.DefaultClient
}

// Name implements Channel.
func (*Vonage) Name() string { return "vonage" }

// Supports implements Channel: SMS only.
func (*Vonage) Supports(kind string) bool { return kind == KindSMS }

// Send implements Channel.
func (v *Vonage) Send(ctx context.Context, m Message) (string, error) {
	endpoint := v.Endpoint
	if endpoint == "" {
		endpoint = "https://rest.nexmo.com/sms/json"
	}
	h := HTTPSMS{ChannelName: v.Name(), Client: v.Client,
		Request: func(ctx context.Context, m Message) (*http.Request, error) {
			body, err := json.Marshal(struct {
				APIKey    string `json:"api_key"`
				APISecret string `json:"api_secret"`
				From      string `json:"from"`
				To        string `json:"to"`
				Text      string `json:"text"`
			}{v.APIKey, v.APISecret, v.From, m.To, m.Text})
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			return req, nil
		},
		ProviderID: func(body []byte) string {
			var r struct {
				Messages []struct {
					ID string `json:"message-id"`
				} `json:"messages"`
			}
			if json.Unmarshal(body, &r) != nil || len(r.Messages) == 0 {
				return ""
			}
			return r.Messages[0].ID
		}}
	return h.Send(ctx, m)
}
