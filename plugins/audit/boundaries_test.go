package audit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

const drainSecret = "a-secret-of-sixteen-chars"

func orgEvent() audit.Event {
	return audit.Event{Name: audit.OrgUpdated, ActorID: "u1", ActorType: audit.ActorUser, OrganizationID: "org1"}
}

// drained records one organization event and waits for the drains: the drain's state after.
func drained(t *testing.T, p *audit.Plugin, id string) audit.Drain {
	t.Helper()
	ctx := context.Background()
	if err := p.Record(ctx, orgEvent()); err != nil {
		t.Fatal(err)
	}
	p.WaitDrains(ctx)
	dr, _, err := p.Drains().Find(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return dr
}

// The default drain client connects to public addresses only, and what a drain's owner reads back
// is a category, not the transport's words (decision 76).
func TestADrainReachesPublicAddressesOnlyAndReportsACategory(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	internal := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer internal.Close()

	p := audit.New(audit.Config{Drains: true, WebhookAttempts: 1})
	polaristest.New(t, polaristest.WithPlugins(p))
	dr, err := p.Drains().Create(ctx, "org1", internal.URL+"/audit", drainSecret, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	after := drained(t, p, dr.ID)
	if hits.Load() != 0 || after.LastError != "refused" {
		t.Fatalf("a loopback endpoint got %d request(s); last_error %q, want \"refused\"", hits.Load(), after.LastError)
	}
}

// Whatever client the host gives, a drain follows no redirect and its failure reads as a category.
func TestADrainFollowsNoRedirectAndEchoesNoTransportError(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	inner := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer inner.Close()
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL+"/internal", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	client := redirecting.Client()
	inner.Client() // both servers share httptest's certificate, so the client trusts the target too
	p := audit.New(audit.Config{HTTPClient: client, WebhookAttempts: 1})
	polaristest.New(t, polaristest.WithPlugins(p))
	dr, err := p.Drains().Create(ctx, "org1", redirecting.URL+"/audit", drainSecret, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if after := drained(t, p, dr.ID); hits.Load() != 0 || after.LastError != "HTTP 307" {
		t.Fatalf("the redirect target got %d request(s); last_error %q, want \"HTTP 307\"", hits.Load(), after.LastError)
	}

	redirecting.Close()
	if after := drained(t, p, dr.ID); after.LastError != "unreachable" {
		t.Fatalf("last_error %q, want \"unreachable\"", after.LastError)
	}
}

// slowTransport holds every request until release is closed (two seconds at most).
type slowTransport struct {
	entered atomic.Int32
	release chan struct{}
}

func (s *slowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.entered.Add(1)
	select {
	case <-s.release:
	case <-time.After(2 * time.Second):
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

// A drain is delivered after the transaction that recorded the event commits, off the writer's
// goroutine, and never for one that rolled back.
func TestADrainNeverHoldsTheTransactionThatRecorded(t *testing.T) {
	ctx := context.Background()
	slow := &slowTransport{release: make(chan struct{})}
	p := audit.New(audit.Config{HTTPClient: &http.Client{Transport: slow}, WebhookAttempts: 1})
	srv := polaristest.New(t, polaristest.WithPlugins(p))
	dr, err := p.Drains().Create(ctx, "org1", "https://hooks.example.test/audit", drainSecret, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	rolledBack := errors.New("rolled back")
	if err := srv.DB.Tx(ctx, func(ctx context.Context) error {
		if err := p.Record(ctx, orgEvent()); err != nil {
			return err
		}
		return rolledBack
	}); !errors.Is(err, rolledBack) {
		t.Fatal(err)
	}
	p.WaitDrains(ctx)
	if n := slow.entered.Load(); n != 0 {
		t.Fatalf("%d delivery(ies) for an event that rolled back", n)
	}

	started := time.Now()
	if err := srv.DB.Tx(ctx, func(ctx context.Context) error {
		if err := p.Record(ctx, orgEvent()); err != nil {
			return err
		}
		if n := slow.entered.Load(); n != 0 {
			t.Errorf("%d delivery(ies) started inside the transaction", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("the writer waited %s for the drain", waited)
	}
	close(slow.release)
	p.WaitDrains(ctx)
	after, _, _ := p.Drains().Find(ctx, dr.ID)
	if slow.entered.Load() != 1 || after.LastDeliveryAt == nil || after.LastError != "" {
		t.Fatalf("after the commit: %d delivery(ies), drain %+v", slow.entered.Load(), after)
	}
}

// An action taken with an operator's impersonation token names the operator on its audit row.
func TestAnImpersonatedActionNamesTheOperator(t *testing.T) {
	p := audit.New(audit.Config{})
	polaristest.New(t, polaristest.WithPlugins(p))
	tok := token.NewPrincipal(map[string]any{"sub": "u1", token.ClaimImpersonatedBy: "op1"})
	ctx := endpoint.WithToken(context.Background(), tok)
	if err := p.Record(ctx, audit.Event{Name: audit.OrgUpdated, ActorID: "u1", ActorType: audit.ActorUser, OrganizationID: "org1", Data: map[string]any{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	page, err := p.Store().Read(context.Background(), audit.Query{})
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("%+v %v", page, err)
	}
	if d := page.Events[0].Data; d["impersonated_by"] != "op1" || d["k"] != "v" {
		t.Fatalf("data %v", d)
	}
}
