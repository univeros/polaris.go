package otel

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/univeros/polaris.go/event"
)

// MetricAuthOutcomes is the counter Listener increments.
const MetricAuthOutcomes = "polaris.auth.outcomes"

// The polaris.auth.outcome values.
const (
	OutcomeLoginSucceeded = "login_succeeded" // user.logged_in
	OutcomeLoginFailed    = "login_failed"    // user.login_failed
	OutcomeAccountLocked  = "account_locked"  // user.locked
	OutcomeRefreshReuse   = "refresh_reuse"   // auth.refresh_reuse_detected
	OutcomeMFAFailed      = "mfa_failed"      // mfa.verify_failed, mfa.otp_verify_failed
	OutcomeAgentExecuted  = "agent_executed"  // agent.executed (plugins/agents)
	OutcomeAgentDenied    = "agent_denied"    // agent.execution_denied (plugins/agents)
)

// outcomes maps an event name to its outcome. The agent names are plugins/agents' EventExecuted
// and EventExecutionDenied, spelled out so importing this package does not link the plugin.
var outcomes = map[string]string{
	event.NameUserLoggedIn:         OutcomeLoginSucceeded,
	event.NameUserLoginFailed:      OutcomeLoginFailed,
	event.NameUserLocked:           OutcomeAccountLocked,
	event.NameRefreshReuseDetected: OutcomeRefreshReuse,
	event.NameMFAVerifyFailed:      OutcomeMFAFailed,
	event.NameOTPVerifyFailed:      OutcomeMFAFailed,
	"agent.executed":               OutcomeAgentExecuted,
	"agent.execution_denied":       OutcomeAgentDenied,
}

// Listener returns the event listener that counts authentication outcomes on the
// polaris.auth.outcomes counter, one increment per event with attribute polaris.auth.outcome
// (see the Outcome* values). Other events are ignored. Subscribe it with Config.Listeners (or on
// your own dispatcher); alert on outcome=refresh_reuse, a spike of login_failed or agent_denied.
// It fails only when the meter provider refuses to create the counter.
func Listener(opts ...Option) (event.Listener, error) {
	c := newConfig(opts)
	counter, err := c.meter().Int64Counter(MetricAuthOutcomes,
		metric.WithDescription("Authentication outcomes: logins, refresh-token reuse, MFA failures, agent executions."),
		metric.WithUnit("{event}"))
	if err != nil {
		return nil, err
	}
	sets := make(map[string]metric.MeasurementOption, len(outcomes))
	for name, outcome := range outcomes {
		sets[name] = metric.WithAttributeSet(attribute.NewSet(attribute.String(AttrOutcome, outcome)))
	}
	return func(ctx context.Context, e event.Event) {
		if set, ok := sets[e.EventName()]; ok {
			counter.Add(ctx, 1, set)
		}
	}, nil
}
