package messaging_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/notify"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/plugins/messaging"
	"github.com/univeros/polaris-go/polaristest"
)

func TestThePluginIsCoresMailerAndSmsSenderAndEverySendIsAudited(t *testing.T) {
	ctx := context.Background()
	mail, sms := messaging.NewMemory("mail", messaging.KindEmail), messaging.NewMemory("sms", messaging.KindSMS)
	p, _ := boot(t, messaging.Config{Email: mail, SMS: sms, Locale: "es"})
	g := p.Graph()

	want(t, g.Mailer() != nil && g.SMS() != nil, "ports")
	found := false
	for _, m := range g.Schema() {
		found = found || m.Table == messaging.TableTemplates
	}
	want(t, found, "the template table joins the schema")

	g.Events().Dispatch(ctx, event.UserRegistered{UserID: "u1", Email: "ada@example.com", VerificationToken: "tok-1"})
	sent := mail.Messages()
	want(t, len(sent) == 1, "the notification listener sent through the plugin: %v", sent)
	verify := sent[0]
	want(t, verify.Kind == "email" && verify.To == "ada@example.com" && verify.Template == "email.verify" &&
		verify.Subject == "Verifica tu dirección de correo", "verify %+v", verify)
	want(t, strings.Contains(verify.Text, "tok-1") && verify.Essential, "verify %+v", verify)

	if err := g.SMS().Send(ctx, "+15551234567", "Your verification code is 123456."); err != nil {
		t.Fatal(err)
	}
	want(t, sms.Messages()[0].Text == "Your verification code is 123456." && sms.Messages()[0].Template == "sms.otp", "sms %+v", sms.Messages())

	user := model.User{ID: "u1", Email: "ada@example.com", Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos().Users.Insert(ctx, user); err != nil {
		t.Fatal(err)
	}
	g.Events().Dispatch(ctx, event.PasswordChanged{UserID: "u1", Method: "reset"})
	want(t, mail.Messages()[1].Template == "email.password_changed" && !mail.Messages()[1].Essential, "password changed %+v", mail.Messages())

	recorded := sentTemplates(t, p)
	want(t, len(recorded) == 3, "recorded %v", recorded)
	var templates []any
	for _, e := range recorded {
		templates = append(templates, e.Data["template"])
	}
	want(t, templates[0] == "email.password_changed" && templates[2] == "email.verify", "newest first: %v", templates)
	verified := recorded[2]
	want(t, verified.Data["recipient_hash"] == hash("ada@example.com"), "hash %v", verified.Data)
	want(t, verified.Data["provider_id"] == "mail-1" && verified.Data["text"] == nil && verified.ActorType == "system", "record %+v", verified)
}

func TestTheConfiguredMailerWinsOverThePlugin(t *testing.T) {
	recording := &notifytest.Mailer{}
	sms := messaging.NewMemory("sms", messaging.KindSMS)
	p, _ := boot(t, messaging.Config{SMS: sms}, func(c *polaris.Config) { c.Mailer = recording })

	want(t, p.Graph().Mailer() == notify.Mailer(recording), "the host's mailer is kept")
	_ = p.Graph().SMS().Send(context.Background(), "+15551234567", "x")
	want(t, len(sms.Messages()) == 1, "the unset port is still the plugin's")
}

// quiet is a switchable Suppressor.
type quiet struct {
	mu sync.Mutex
	on bool
}

func (q *quiet) Suppresses(context.Context, messaging.Message) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.on
}

func TestThePolicyCapsRecipientsFallsBackAndKeepsQuiet(t *testing.T) {
	ctx := context.Background()
	mail, sms := messaging.NewMemory("mail", messaging.KindEmail), messaging.NewMemory("sms", messaging.KindSMS)
	sms.SetFailing(true)
	q := &quiet{}
	_, plugin := boot(t, messaging.Config{SMS: sms, Email: mail, Suppressor: q,
		Caps: map[string]messaging.Cap{"*": {2, 10 * time.Minute}, "email.otp": {1, 10 * time.Minute}}})
	s := plugin.Sender()
	send := func(to, template string, vars map[string]any) error {
		_, err := s.Send(ctx, messaging.Message{Kind: messaging.KindEmail, To: to, Template: template, Vars: vars}, nil)
		return err
	}
	tok := map[string]any{"token": "t"}

	want(t, send("ada@example.com", "email.verify", tok) == nil, "first")
	want(t, send("ADA@example.com", "email.verify", tok) == nil, "second")
	want(t, errors.Is(send("ada@example.com", "email.verify", tok), messaging.ErrRefused), "the third in the window is refused, case-insensitively")
	want(t, send("bob@example.com", "email.verify", tok) == nil, "another recipient has their own cap")
	want(t, send("ada@example.com", "email.otp", map[string]any{"code": 1, "ttl": 9}) == nil, "otp")
	want(t, errors.Is(send("ada@example.com", "email.otp", map[string]any{"code": 1, "ttl": 9}), messaging.ErrRefused), "the template cap")
	want(t, len(mail.Messages()) == 4, "4 mails, got %d", len(mail.Messages()))

	r, err := s.Send(ctx, messaging.Message{Kind: messaging.KindSMS, To: "+15551234567", Template: "sms.otp", Vars: map[string]any{"code": 7}},
		map[string]string{messaging.KindEmail: "ada@example.com"})
	want(t, err == nil && r.Channel == "mail", "the SMS channel failed, the email sibling went instead: %+v %v", r, err)
	last := mail.Messages()[4]
	want(t, last.Template == "email.otp" && last.Text == "Your verification code is 7. It expires in {ttl} seconds.", "fallback %+v", last)
	_, err = s.Send(ctx, messaging.Message{Kind: messaging.KindSMS, To: "+15557654321", Template: "sms.otp", Vars: map[string]any{"code": 7}}, nil)
	want(t, errors.Is(err, messaging.ErrUndelivered), "no alternative, no fallback: %v", err)

	q.mu.Lock()
	q.on = true
	q.mu.Unlock()
	nd := map[string]any{"ip": "1", "user_agent": "x"}
	want(t, errors.Is(send("carol@example.com", "email.new_device", nd), messaging.ErrRefused), "quiet mode drops a non-essential message")
	_, err = s.Send(ctx, messaging.Message{Kind: messaging.KindEmail, To: "carol@example.com", Template: "email.verify", Vars: tok, Essential: true}, nil)
	want(t, err == nil, "an essential one still goes: %v", err)
}

// queue is an Outbox that keeps each send as JSON, as a real queue would.
type queue struct {
	mu   sync.Mutex
	jobs [][]byte
}

type job struct {
	Message      messaging.Message
	Alternatives map[string]string
}

func (q *queue) Push(_ context.Context, m messaging.Message, alternatives map[string]string) (messaging.Receipt, error) {
	raw, err := json.Marshal(job{m, alternatives})
	if err != nil {
		return messaging.Receipt{}, err
	}
	q.mu.Lock()
	q.jobs = append(q.jobs, raw)
	q.mu.Unlock()
	return messaging.Queued(now), nil
}

func TestAQueueOutboxTakesTheSendAsDataAndItsWorkerDeliversItOnce(t *testing.T) {
	ctx := context.Background()
	mail, sms := messaging.NewMemory("mail", messaging.KindEmail), messaging.NewMemory("sms", messaging.KindSMS)
	sms.SetFailing(true)
	q := &queue{}
	p, plugin := boot(t, messaging.Config{SMS: sms, Email: mail, Outbox: q,
		Caps: map[string]messaging.Cap{"sms.otp": {1, 10 * time.Minute}, "*": messaging.DefaultCap}})
	s := plugin.Sender()
	otp := func(code int) messaging.Message {
		return messaging.Message{Kind: messaging.KindSMS, To: "+15551234567", Template: "sms.otp", Vars: map[string]any{"code": code}}
	}

	r, err := s.Send(ctx, otp(7), map[string]string{messaging.KindEmail: "ada@example.com"})
	want(t, err == nil && r.Queued && r.Channel == messaging.ChannelQueued, "a deferred send answers a queued receipt: %+v %v", r, err)
	want(t, len(mail.Messages()) == 0, "nothing is delivered on the request")
	_, err = s.Send(ctx, otp(8), nil)
	want(t, errors.Is(err, messaging.ErrRefused), "the policy counted the queued send: %v", err)

	var j job
	if err := json.Unmarshal(q.jobs[0], &j); err != nil { // the worker
		t.Fatal(err)
	}
	delivered, err := s.Dispatch(ctx, j.Message, j.Alternatives)
	want(t, err == nil && delivered.Channel == "mail" && !delivered.Queued, "the worker delivers through the fallback: %+v %v", delivered, err)
	want(t, mail.Messages()[0].Template == "email.otp", "fallback template")
	want(t, len(q.jobs) == 1, "dispatch never comes back to the outbox")
	want(t, len(sentTemplates(t, p)) == 1, "one delivery, recorded once")

	r, err = plugin.SendTemplate(ctx, "bob@example.com", "email.otp", `{"code":"1","ttl":60}`, "")
	want(t, err == nil && r.Queued, "the send command queues too: %+v %v", r, err)
}

func TestTheSendCommandRunsOnTheApplicationsGraph(t *testing.T) {
	ctx := context.Background()
	mail := messaging.NewMemory("mail", messaging.KindEmail)
	_, plugin := boot(t, messaging.Config{Email: mail})

	r, err := plugin.SendTemplate(ctx, "ada@example.com", "email.otp", `{"code":"424242","ttl":300}`, "fr")
	want(t, err == nil && r.Channel == "mail", "sent through mail: %+v %v", r, err)
	want(t, mail.Messages()[0].Text == "Votre code de vérification est 424242. Il expire dans 300 secondes.", "text %q", mail.Messages()[0].Text)
	_, err = plugin.SendTemplate(ctx, "ada@example.com", "email.otp", "nope", "")
	want(t, err != nil && strings.Contains(err.Error(), "JSON object"), "bad vars: %v", err)
	_, err = plugin.SendTemplate(ctx, "+1555", "sms.otp", `{"code":"1"}`, "")
	want(t, errors.Is(err, messaging.ErrUndelivered), "no SMS channel configured: %v", err)
}

func TestTheDefaultChannelIsTheLogAndPolarisTestCanUseThePorts(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithoutRecorders(), polaristest.WithPlugins(messaging.New(messaging.Config{})))
	err := srv.Graph().Mailer().Send(context.Background(), "ada@example.com", notify.TemplateOTPCode, map[string]any{"code": "1", "ttl": 60})
	want(t, err == nil, "the log channel delivers: %v", err)
	want(t, len(srv.Mailer.Sent()) == 0, "the recorder is unused")
	want(t, messaging.Of(srv.Graph()) != nil, "Of")
}

func TestABadCapFailsNew(t *testing.T) {
	_, err := start(t, messaging.Config{Caps: map[string]messaging.Cap{"*": {0, time.Minute}}})
	want(t, err != nil && strings.Contains(err.Error(), "Config.Caps"), "an invalid cap fails New: %v", err)
}
