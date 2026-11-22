package audit

import (
	"testing"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/token"
)

// An event dispatched while serving a request records that request's client, as api_keys.* do;
// what the event itself says about its client wins.
func TestEventsRecordTheRequestsClient(t *testing.T) {
	s := &spy{}
	r := newRecorder(t, s)
	req := endpoint.WithClient(ctx, token.ClientContext{IP: "203.0.113.7", UserAgent: "curl/8"})
	r.Listen(req, event.OrganizationCreated{OrganizationID: "org1", Slug: "acme", OwnerUserID: "u1"})
	r.Listen(req, event.MemberInvited{OrganizationID: "org1", Email: "a@example.test", InvitedBy: "u1"})
	r.Listen(req, event.UserLoggedIn{UserID: "u1", IP: strp("198.51.100.1")})
	r.Listen(ctx, event.OrganizationUpdated{OrganizationID: "org1", ActorUserID: "u1"})
	if len(s.events) != 4 {
		t.Fatalf("%d events", len(s.events))
	}
	for _, e := range s.events[:2] {
		if e.IP != "203.0.113.7" || e.UserAgent != "curl/8" {
			t.Fatalf("%s: ip %q ua %q", e.Name, e.IP, e.UserAgent)
		}
	}
	if in := s.events[2]; in.IP != "198.51.100.1" || in.UserAgent != "curl/8" {
		t.Fatalf("the event's own IP wins: %+v", in)
	}
	if out := s.events[3]; out.IP != "" || out.UserAgent != "" {
		t.Fatalf("no request, no client: %+v", out)
	}
}
