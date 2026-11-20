package token

import "testing"

func TestPrincipalAndDelegation(t *testing.T) {
	claims := map[string]any{"sub": "u1", "org": "o1"}
	p := NewPrincipal(claims)
	claims["sub"] = "changed"
	if p.Subject() != "u1" || p.Organization() != "o1" || p.Raw() != "" || p.Header("kid") != nil {
		t.Fatalf("principal %v", p.Claims())
	}
	if _, ok := p.Delegation(); ok {
		t.Fatal("fresh principal must not be delegated")
	}
	d := p.Delegate([]string{"a.read"})
	perms, ok := d.Delegation()
	if !ok || len(perms) != 1 || perms[0] != "a.read" {
		t.Fatalf("delegation %v %v", perms, ok)
	}
	if _, ok := p.Delegation(); ok {
		t.Fatal("Delegate must not change the receiver")
	}
	perms[0] = "x"
	if again, _ := d.Delegation(); again[0] != "a.read" {
		t.Fatal("Delegation must copy")
	}
	if perms, ok := p.Delegate(nil).Delegation(); !ok || perms == nil || len(perms) != 0 {
		t.Fatal("nil permissions delegate nothing")
	}
	if NewPrincipal(map[string]any{"delegated": []any{"x"}}).Organization() != "" {
		t.Fatal("org")
	}
	if _, ok := NewPrincipal(map[string]any{"delegated": []any{"x"}}).Delegation(); ok {
		t.Fatal("a delegated claim must never mark delegation")
	}
}
