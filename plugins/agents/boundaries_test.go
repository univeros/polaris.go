package agents

import (
	"context"
	"testing"
	"time"
)

// A grant the policy approved and the agent spent is not approved again by the policy while its
// window lasts: the next request waits for a person (decision 76).
func TestASpentAutoApprovedBudgetIsNotRefilledByAskingAgain(t *testing.T) {
	for name, policy := range map[string]Budget{"a window": {Count: 2, Window: time.Hour}, "no window": {Count: 2}} {
		t.Run(name, func(t *testing.T) {
			p, srv := bootUnit(t, Config{AutoApprove: map[string]Budget{RiskLow: policy}})
			ctx := context.Background()
			a := holder(t, p, srv)
			ask := func() Grant {
				res, err := p.s.requestGrants(ctx, a, []any{"members"})
				must(t, err)
				return res.grants[0]
			}
			first := ask()
			if first.Status != GrantActive || first.ApprovedVia != ViaAuto || *first.BudgetTotal != 2 {
				t.Fatalf("first %+v", first)
			}
			if left, ok, err := p.s.spend(ctx, first, 2); err != nil || !ok || *left != 0 {
				t.Fatalf("spend: %v %v %v", left, ok, err)
			}
			_, err := p.s.endGrant(ctx, first, []string{GrantActive}, GrantExhausted)
			must(t, err)

			again := ask()
			if again.Status != GrantPending || again.ID == first.ID {
				t.Fatalf("asking again after spending the budget: %s (via %q), want pending", again.Status, again.ApprovedVia)
			}
			// A person may still approve it.
			if _, err := p.s.approveGrant(ctx, again, "owner", MethodInApp, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Once the spent grant's window has passed, the policy applies again.
func TestThePolicyAppliesAgainAfterTheSpentGrantsWindow(t *testing.T) {
	p, srv := bootUnit(t, Config{AutoApprove: map[string]Budget{RiskLow: {Count: 2, Window: time.Hour}}})
	ctx := context.Background()
	a := holder(t, p, srv)
	res, err := p.s.requestGrants(ctx, a, []any{"members"})
	must(t, err)
	first := res.grants[0]
	_, err = p.s.endGrant(ctx, first, []string{GrantActive}, GrantExhausted)
	must(t, err)
	past := p.s.now().Add(-time.Minute)
	if _, err := p.s.db.Update(ctx, TableGrants, map[string]any{"id": first.ID}, map[string]any{"expires_at": past}); err != nil {
		t.Fatal(err)
	}
	res, err = p.s.requestGrants(ctx, a, []any{"members"})
	must(t, err)
	if g := res.grants[0]; g.Status != GrantActive || g.ApprovedVia != ViaAuto {
		t.Fatalf("after the window: %+v", g)
	}
}
