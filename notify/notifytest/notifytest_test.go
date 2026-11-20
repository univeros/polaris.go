package notifytest

import (
	"context"
	"sync"
	"testing"

	"github.com/univeros/polaris-go/notify"
)

var (
	_ notify.Mailer    = (*Mailer)(nil)
	_ notify.SMSSender = (*SMSSender)(nil)
)

func TestMailerRecordsWhatItWasAskedToSend(t *testing.T) {
	m := &Mailer{}
	data := map[string]any{"code": "123456"}
	_ = m.Send(context.Background(), "ada@example.com", notify.TemplateOTPCode, data)
	data["code"] = "changed"

	sent := m.Sent()
	if len(sent) != 1 || sent[0].To != "ada@example.com" || sent[0].Template != "otp_code" || sent[0].Data["code"] != "123456" {
		t.Fatalf("sent = %+v", sent)
	}
	sent[0].To = "x"
	if m.Sent()[0].To != "ada@example.com" {
		t.Fatal("Sent must return a copy")
	}
}

func TestSMSSenderRecordsWhatItWasAskedToSend(t *testing.T) {
	s := &SMSSender{}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { _ = s.Send(context.Background(), "+14155550101", "Your code is 123456") })
	}
	wg.Wait()
	sent := s.Sent()
	if len(sent) != 10 || sent[0].To != "+14155550101" || sent[0].Message != "Your code is 123456" {
		t.Fatalf("sent = %+v", sent)
	}
}
