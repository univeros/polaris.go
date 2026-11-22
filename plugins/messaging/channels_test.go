package messaging

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"testing"
)

func check(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}

// provider is a fake SMS API: it records the request and answers status with body.
func provider(t *testing.T, status int, body string) (*httptest.Server, *http.Request, *[]byte) {
	t.Helper()
	var got http.Request
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r.Clone(context.Background())
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &raw
}

var otp = Message{Kind: KindSMS, To: "+15551234567", Template: "sms.otp", Text: "Your code is 1."}

func TestTwilioPostsAFormAndReadsTheSid(t *testing.T) {
	srv, req, body := provider(t, 201, `{"sid":"SM123"}`)
	ch := &Twilio{AccountSID: "AC1", AuthToken: "secret", From: "+15550000000", BaseURL: srv.URL}

	check(t, ch.Supports(KindSMS) && !ch.Supports(KindEmail), "SMS only")
	id, err := ch.Send(context.Background(), otp)
	check(t, err == nil && id == "SM123" && ch.Name() == "twilio", "%q %v", id, err)
	check(t, req.URL.Path == "/2010-04-01/Accounts/AC1/Messages.json" && req.Method == http.MethodPost, "url %s", req.URL)
	check(t, req.Header.Get("Authorization") == "Basic "+base64.StdEncoding.EncodeToString([]byte("AC1:secret")), "auth")
	form, _ := url.ParseQuery(string(*body))
	check(t, form.Get("To") == "+15551234567" && form.Get("From") == "+15550000000" && form.Get("Body") == "Your code is 1." && len(form) == 3, "form %v", form)
}

func TestVonagePostsJsonAndAFailureIsADeliveryException(t *testing.T) {
	srv, _, body := provider(t, 200, `{"messages":[{"message-id":"0A0000"}]}`)
	ch := &Vonage{APIKey: "key", APISecret: "secret", From: "Polaris", Endpoint: srv.URL}
	id, err := ch.Send(context.Background(), otp)
	check(t, err == nil && id == "0A0000", "%q %v", id, err)
	check(t, string(*body) == `{"api_key":"key","api_secret":"secret","from":"Polaris","to":"+15551234567","text":"Your code is 1."}`, "body %s", *body)

	down, _, _ := provider(t, 503, "")
	_, err = (&Vonage{Endpoint: down.URL}).Send(context.Background(), otp)
	check(t, err != nil && strings.Contains(err.Error(), "HTTP 503"), "err %v", err)
	_, err = (&Vonage{Endpoint: "http://127.0.0.1:1"}).Send(context.Background(), otp)
	check(t, err != nil, "a transport failure is an error")
	check(t, (&Vonage{}).Name() == "vonage" && !(&Vonage{}).Supports(KindEmail), "vonage")
}

func TestAGenericHTTPSMSChannelBuildsTheProvidersRequest(t *testing.T) {
	srv, req, body := provider(t, 202, `{"id":"x-1"}`)
	ch := &HTTPSMS{ChannelName: "acme",
		Request: func(ctx context.Context, m Message) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPut, srv.URL+"/send?to="+url.QueryEscape(m.To), strings.NewReader(m.Text))
		},
		ProviderID: func(b []byte) string { return strings.TrimSuffix(strings.TrimPrefix(string(b), `{"id":"`), `"}`) }}
	id, err := ch.Send(context.Background(), otp)
	check(t, err == nil && id == "x-1" && ch.Name() == "acme", "%q %v", id, err)
	check(t, req.Method == http.MethodPut && req.URL.Query().Get("to") == "+15551234567" && string(*body) == "Your code is 1.", "request")

	_, err = (&HTTPSMS{}).Send(context.Background(), otp)
	check(t, err != nil && (&HTTPSMS{}).Name() == "http_sms", "no Request")
	_, err = (&HTTPSMS{Request: func(context.Context, Message) (*http.Request, error) { return nil, errors.New("nope") }}).Send(context.Background(), otp)
	check(t, err != nil, "a request error")
	id, err = (&HTTPSMS{Request: func(ctx context.Context, m Message) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
	}}).Send(context.Background(), otp)
	check(t, err == nil && id == "", "no ProviderID: %q %v", id, err)
}

func TestSmtpSendsSubjectTextAndHtml(t *testing.T) {
	var gotFrom string
	var gotTo []string
	var raw []byte
	ch := &SMTP{Addr: "smtp.test:25", From: "Acme <noreply@example.test>",
		send: func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			gotFrom, gotTo, raw = from, to, msg
			return nil
		}}
	check(t, ch.Supports(KindEmail) && !ch.Supports(KindSMS) && ch.Name() == "smtp", "email only")

	id, err := ch.Send(context.Background(), Message{Kind: KindEmail, To: "ada@example.com", Template: "email.otp", Text: "Code 1", Subject: "Votre code é", HTML: "<b>1</b>"})
	check(t, err == nil && strings.HasSuffix(id, "@example.test>"), "%q %v", id, err)
	check(t, gotFrom == "noreply@example.test" && len(gotTo) == 1 && gotTo[0] == "ada@example.com", "envelope %s %v", gotFrom, gotTo)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	check(t, subject == "Votre code é" && msg.Header.Get("Message-Id") == id && msg.Header.Get("To") == "<ada@example.com>", "headers %v", msg.Header)
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	parts := multipart.NewReader(msg.Body, params["boundary"])
	var bodies []string
	for {
		part, err := parts.NextPart() // decodes quoted-printable
		if err != nil {
			break
		}
		b, _ := io.ReadAll(part)
		bodies = append(bodies, string(b))
	}
	check(t, len(bodies) == 2 && bodies[0] == "Code 1" && bodies[1] == "<b>1</b>", "parts %q", bodies)

	_, err = ch.Send(context.Background(), Message{Kind: KindEmail, To: "ada@example.com", Text: "plain", Subject: "s"})
	check(t, err == nil && strings.Contains(string(raw), "text/plain") && !strings.Contains(string(raw), "multipart"), "plain %s", raw)
}

func TestSmtpRefusesBadAddressesAndReportsTheServer(t *testing.T) {
	fail := &SMTP{From: "noreply@example.test", send: func(string, smtp.Auth, string, []string, []byte) error { return errors.New("SMTP down") }}
	_, err := fail.Send(context.Background(), Message{To: "ada@example.com", Text: "x"})
	check(t, err != nil && strings.Contains(err.Error(), "SMTP down"), "%v", err)
	_, err = fail.Send(context.Background(), Message{To: "not an address", Text: "x"})
	check(t, err != nil, "bad recipient")
	_, err = (&SMTP{From: "nope"}).Send(context.Background(), Message{To: "ada@example.com"})
	check(t, err != nil, "bad From")
	_, err = fail.Send(context.Background(), Message{To: "ada@example.com", Subject: "a\r\nBcc: eve@example.com"})
	check(t, err != nil && strings.Contains(err.Error(), "line break"), "header injection refused: %v", err)
}

func TestTheLogAndArrayChannels(t *testing.T) {
	var buf bytes.Buffer
	log := &Log{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	id, err := log.Send(context.Background(), Message{Kind: KindSMS, To: "+1", Template: "sms.otp", Text: "Code 1"})
	check(t, err == nil && id == "" && log.Name() == "log" && log.Supports("anything"), "log")
	check(t, strings.Contains(buf.String(), "sms.otp") && strings.Contains(buf.String(), "+1"), "the template and recipient are logged: %s", buf.String())
	check(t, !strings.Contains(buf.String(), "Code 1"), "the body is not logged unless asked: %s", buf.String())
	_, _ = (&Log{}).Send(context.Background(), Message{})
	buf.Reset()
	_, _ = (&Log{Logger: slog.New(slog.NewTextHandler(&buf, nil)), Bodies: true}).Send(context.Background(), Message{Kind: KindSMS, To: "+1", Template: "sms.otp", Text: "Code 1"})
	check(t, strings.Contains(buf.String(), "Code 1"), "Bodies logs the body: %s", buf.String())

	mem := NewMemory("mail", KindEmail)
	check(t, !mem.Supports(KindSMS) && NewMemory("").Name() == "memory" && NewMemory("").Supports(KindSMS), "kinds")
	id, err = mem.Send(context.Background(), Message{Kind: KindEmail, To: "a@b.c"})
	check(t, err == nil && id == "mail-1", "%q %v", id, err)
	mem.SetFailing(true)
	_, err = mem.Send(context.Background(), Message{})
	check(t, err != nil && len(mem.Messages()) == 1, "failing")
}
