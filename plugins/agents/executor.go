package agents

import (
	"context"
	"fmt"

	"github.com/univeros/polaris-go/store"
)

// evaluation is an execution that passed every check before anything is spent.
type evaluation struct {
	principal  principal
	capability *Capability
	grant      Grant
	arguments  map[string]any
	inputHash  string
	cost       int64
}

// execution is what an execution produced.
type execution struct {
	result    any
	receipt   Receipt
	exhausted bool
}

func (e execution) view() map[string]any {
	return map[string]any{"data": e.result, "receipt": map[string]any{"id": e.receipt.ID, "seq": e.receipt.Seq, "hash": e.receipt.Hash}}
}

// arguments reads the arguments of a call: an object, or nothing (PHP's empty [] included).
func arguments(v any) (map[string]any, bool) {
	switch v := v.(type) {
	case nil:
		return map[string]any{}, true
	case map[string]any:
		return v, true
	case []any:
		return map[string]any{}, len(v) == 0
	}
	return nil, false
}

// evaluate runs the checks: the capability exists; the credential may use it (the JWT names it,
// the token carries its permission); the agent holds a live grant for it; the owner still holds
// the permission; the arguments match the input schema and the grant's constraints.
func (s *service) evaluate(ctx context.Context, p principal, name string, raw any) (evaluation, error) {
	capability := s.caps.find(name)
	if capability == nil {
		return evaluation{}, refuse(ErrCapabilityNotFound, fmt.Sprintf("Unknown capability \"%s\".", name))
	}
	if !p.mayUse(name) {
		return evaluation{}, refuse(ErrCapabilityNotGranted, "The request JWT does not name this capability.")
	}
	if !p.carries(capability.Permission) {
		return evaluation{}, refuse(ErrCapabilityNotGranted, fmt.Sprintf("The token does not carry the permission \"%s\" the capability requires.", capability.Permission))
	}
	g, err := s.activeGrant(ctx, p.agent, name)
	if err != nil {
		return evaluation{}, err
	}
	if g == nil {
		return evaluation{}, refuse(ErrCapabilityNotGranted, fmt.Sprintf("The agent holds no active grant for \"%s\".", name))
	}
	holds, err := s.ownerHolds(ctx, p.agent, capability.Permission)
	if err != nil {
		return evaluation{}, err
	}
	if !holds {
		return evaluation{}, refuse(ErrCapabilityNotGranted, fmt.Sprintf("The agent's owner no longer holds the permission \"%s\".", capability.Permission))
	}
	args, ok := arguments(raw)
	if !ok {
		return evaluation{}, &Error{Type: ErrInvalidArguments, Detail: "arguments is an object.", Extra: map[string]any{"errors": []string{"arguments is an object"}}}
	}
	if msg := validateSchema(capability.Input, args); msg != "" {
		return evaluation{}, &Error{Type: ErrInvalidArguments, Detail: "The arguments do not match the capability's input schema.", Extra: map[string]any{"errors": []string{msg}}}
	}
	if v := violations(g.Constraints, args); len(v) > 0 {
		return evaluation{}, &Error{Type: ErrConstraintViolated, Detail: "The arguments violate the grant's constraints.", Extra: map[string]any{"violations": v}}
	}
	c, err := cost(*g, args)
	if err != nil {
		return evaluation{}, err
	}
	return evaluation{principal: p, capability: capability, grant: *g, arguments: args, inputHash: inputHash(args), cost: c}, nil
}

// run spends the budget, runs the handler and appends the receipt in one transaction, holding the
// agent's row from the start (the kill switch and an execution serialise on it: an agent revoked
// or suspended meanwhile runs nothing). The handler's error rolls everything back. outcome reads
// the receipt's outcome from the handler's result (nil: success).
func (s *service) run(ctx context.Context, ev evaluation, handler func(context.Context, Call) (any, error), outcome func(any) string, c client) (execution, error) {
	a, g := ev.principal.agent, ev.grant
	var out execution
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID, "status": StatusActive}, store.Data{"updated_at": s.now()})
		if err != nil {
			return err
		}
		if n != 1 {
			current, _, err := s.agent(ctx, a.ID)
			if err != nil {
				return err
			}
			if current.Status == "" {
				current.Status = StatusRevoked
			}
			return assertActive(current)
		}
		before := g.BudgetRemaining
		after, ok, err := s.spend(ctx, g, ev.cost)
		if err != nil {
			return err
		}
		if !ok && g.BudgetKind == "" {
			return refuse(ErrCapabilityNotGranted, fmt.Sprintf("The agent holds no active grant for \"%s\".", g.Capability))
		}
		if !ok {
			return refuse(ErrBudgetExhausted, fmt.Sprintf("The grant's budget cannot cover this execution (%d left).", deref64(before)))
		}
		g.BudgetRemaining = after
		result, err := handler(ctx, Call{Agent: a, Grant: g, Capability: ev.capability.Name, Arguments: ev.arguments, InputHash: ev.inputHash})
		if err != nil {
			return err
		}
		o := OutcomeSuccess
		if outcome != nil {
			o = outcome(result)
		}
		r, err := s.appendReceipt(ctx, a, &g, ev.capability.Name, ev.inputHash, o, before, after)
		if err != nil {
			return err
		}
		out = execution{result: result, receipt: r, exhausted: after != nil && *after == 0}
		if out.exhausted {
			_, err = s.endGrant(ctx, g, []string{GrantActive}, GrantExhausted)
		}
		return err
	})
	if err != nil {
		if e, ok := asError(err); ok {
			s.deny(ctx, a, ev.capability.Name, e, c)
		}
		return execution{}, err
	}
	s.dispatch(ctx, byAgent(EventExecuted, a, map[string]any{"capability": ev.capability.Name, "receipt_id": out.receipt.ID, "seq": out.receipt.Seq, "outcome": out.receipt.Outcome}, c))
	if out.exhausted {
		if err := s.syncClientScopes(ctx, a); err != nil {
			s.log.ErrorContext(ctx, "agents: syncing the client scopes after an exhausted grant failed", "agent", a.ID, "error", err)
		}
		s.dispatch(ctx, byAgent(EventGrantExhausted, a, map[string]any{"capability": g.Capability, "grant_id": g.ID}, c))
	}
	return out, nil
}

func deref64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// execute is POST /agents/execute and the MCP tools: the capability's configured handler.
func (s *service) execute(ctx context.Context, p principal, name string, raw any, c client) (execution, error) {
	ev, err := s.evaluate(ctx, p, name, raw)
	if err == nil && ev.capability.Handler == nil {
		err = refuse(ErrCapabilityNotGranted, fmt.Sprintf("\"%s\" runs at its location, %s, not here.", name, ev.capability.Location))
	}
	if err != nil {
		if e, ok := asError(err); ok {
			s.deny(ctx, p.agent, name, e, c)
		}
		return execution{}, err
	}
	return s.run(ctx, ev, ev.capability.Handler, nil, c)
}

// deny records a refusal as agent.execution_denied.
func (s *service) deny(ctx context.Context, a Agent, capability string, e *Error, c client) {
	s.dispatch(ctx, byAgent(EventExecutionDenied, a, map[string]any{"capability": null(capability), "error": e.code(), "detail": e.Detail}, c))
}
