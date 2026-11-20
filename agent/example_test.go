package agent_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/agent"
)

// The walkthrough: discover, enrol through a host, request grants, wait for the person to approve
// what the policy did not, execute, verify the receipt chain. The server here is an in-process
// stand-in; against a real one, pass its URL and the host's enrollment token.
func Example() {
	server := newFakePolaris()
	defer server.Close()
	ctx := context.Background()

	key, err := agent.GenerateKey(agent.EdDSA) // keep key.Export() somewhere safe for the next run
	if err != nil {
		log.Fatal(err)
	}
	a, err := agent.New(ctx, server.URL+"/auth", agent.WithKey(key))
	if err != nil {
		log.Fatal(err)
	}
	bot, enrolled, err := a.Enroll(ctx, enrollmentToken, agent.Registration{Name: "Worker", Mode: agent.Delegated})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("enrolled:", enrolled.Name, enrolled.Auth)

	asked, err := bot.RequestGrants(ctx, agent.GrantRequest{
		Capabilities: []agent.CapabilityRequest{{Name: "demo.echo"}, {Name: "deploy.production"}},
		Reason:       "Ship 1.4.2",
	})
	if err != nil {
		log.Fatal(err)
	}
	if asked.Approval != nil { // what the policy did not approve waits for a person
		fmt.Println("approve at", asked.Approval.VerificationURIComplete)
		grants, err := bot.WaitForApproval(ctx, *asked.Approval) // ErrApprovalDenied, ErrApprovalExpired, ctx's error
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("approved:", grants[0].Capability)
	}

	res, err := bot.Execute(ctx, "deploy.production", map[string]string{"build": "1.4.2"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("result:", string(res.Data), "receipt", res.Receipt.Seq)
	if _, err := bot.Execute(ctx, "billing.refund", nil); errors.Is(err, agent.ErrCapabilityNotGranted) {
		if e, ok := errors.AsType[*agent.Error](err); ok {
			fmt.Println("refused:", e.Status)
		}
	}

	chain := ownerReceipts(server, bot.ID()) // the owner's GET /agents/{id}/receipts
	check, err := bot.VerifyReceipt(ctx, chain[0], nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("receipt valid:", check.Valid)
	// Output:
	// enrolled: Worker private_key_jwt
	// approve at https://app.example.com/approve?user_code=BTMR-XVSK
	// approved: deploy.production
	// result: {"echo":{"build":"1.4.2"}} receipt 1
	// refused: 403
	// receipt valid: true
}

// A restarted agent loads its stored key and its id instead of enrolling again.
func ExampleImportKey() {
	key, err := agent.GenerateKey(agent.ES256)
	if err != nil {
		log.Fatal(err)
	}
	stored, err := key.Export() // the private key: a secrets manager or a 0600 file, never a log
	if err != nil {
		log.Fatal(err)
	}

	again, err := agent.ImportKey(stored)
	if err != nil {
		log.Fatal(err)
	}
	// then: agent.New(ctx, serverURL, agent.WithKey(again), agent.WithID(savedID))
	fmt.Println(again.Alg(), again.KID() == key.KID())
	// Output: ES256 true
}

// A capability with a Location runs at the host behind Polaris' request middleware: Do signs the
// request JWT for that exact URL and body.
func ExampleAgent_Do() {
	server := newFakePolaris()
	defer server.Close()
	ctx := context.Background()
	key, _ := agent.GenerateKey(agent.EdDSA)
	a, _ := agent.New(ctx, server.URL+"/auth", agent.WithKey(key))
	bot, _, _ := a.Enroll(ctx, enrollmentToken, agent.Registration{Name: "Inviter", Mode: agent.Delegated})
	if _, err := bot.RequestGrants(ctx, agent.GrantRequest{Capabilities: []agent.CapabilityRequest{{Name: "members.invite"}}}); err != nil {
		log.Fatal(err)
	}

	location := server.URL + "/auth/host/invite" // the Location Capabilities lists for members.invite
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, location, strings.NewReader(`{"email":"ada@acme.test"}`))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := bot.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode, resp.Header.Get("X-Polaris-Receipt") != "")
	// Output: 201 true
}
