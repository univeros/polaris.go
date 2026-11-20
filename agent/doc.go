// Package agent is the Go agent SDK of Polaris: how a Go program signs in to a Polaris server as
// an AI agent (the plugins/agents protocol). It discovers the server, registers or enrols the
// agent, requests capability grants and waits for a person to approve them, signs every call with
// a request JWT bound to its exact URL, method and body, executes capabilities, mints OAuth tokens
// (client credentials with private_key_jwt, token exchange for a delegated agent) and verifies the
// server's signed receipt chain.
//
// The whole integration:
//
//	key, _ := agent.GenerateKey(agent.ES256)            // persist key.Export() for the next run
//	a, err := agent.New(ctx, "https://app.example.com/auth", agent.WithKey(key))
//	bot, _, err := a.Enroll(ctx, os.Getenv("POLARIS_ENROLLMENT_TOKEN"),
//		agent.Registration{Name: "Worker", Mode: agent.Delegated})
//	asked, err := bot.RequestGrants(ctx, agent.GrantRequest{
//		Capabilities: []agent.CapabilityRequest{{Name: "deploy.staging"}}})
//	if asked.Approval != nil {                          // what the policy did not approve waits
//		fmt.Println("approve at", asked.Approval.VerificationURIComplete)
//		_, err = bot.WaitForApproval(ctx, *asked.Approval) // ErrApprovalDenied, ErrApprovalExpired
//	}
//	res, err := bot.Execute(ctx, "deploy.staging", map[string]any{"build": "1.4.2"})
//
// A refusal is an *Error with the HTTP status, the problem's code (match it with errors.Is
// against ErrBudgetExhausted, ErrConstraintViolated, ...) and the RFC 9457 problem document.
// A capability with a Location runs at the host: call it with Agent.Do.
//
// The wire behaviour is upstream's (polaris-core packages/agent and agent-ts): the same requests,
// the same JWTs, the same receipt checks; the PHP server verifies the JWTs this package signs.
package agent
