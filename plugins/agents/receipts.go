package agents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

// ReceiptJWTType is the typ header of a receipt signature (verifiable with core's JWKS).
const ReceiptJWTType = "receipt+jwt"

const maxReceiptPage = 200

// appendReceipt appends the next receipt of the agent's chain, signed with core's key; the caller
// holds the transaction. The unique (agent_id, seq) makes a concurrent append fail (conflict)
// rather than fork the chain; nothing is chained after a sealed receipt.
func (s *service) appendReceipt(ctx context.Context, a Agent, g *Grant, capability, input, outcome string, before, after *int64) (Receipt, error) {
	prev, ok, err := s.lastReceipt(ctx, a.ID)
	if err != nil {
		return Receipt{}, err
	}
	if ok && prev.Outcome == OutcomeSealed {
		return Receipt{}, refuse(ErrSealed, "The agent's receipt chain is sealed.")
	}
	signedAt := s.clock.Now().Truncate(time.Microsecond)
	r := Receipt{ID: newID(), AgentID: a.ID, Seq: 1, Capability: capability, InputHash: input, Outcome: outcome,
		BudgetBefore: before, BudgetAfter: after, CreatedAt: signedAt.UTC().Truncate(time.Second)}
	if ok {
		r.Seq, r.PrevHash = prev.Seq+1, prev.Hash
	}
	if g != nil {
		r.GrantID = g.ID
	}
	r.Hash = hashOf(r)
	if r.Signature, err = s.codec.Sign(ReceiptJWTType, token.Claims{}.With("iat", signedAt).With("receipt_hash", r.Hash).
		With("receipt_id", r.ID).With("agent_id", r.AgentID).With("seq", r.Seq)); err != nil {
		return Receipt{}, err
	}
	if err := s.db.Insert(ctx, TableReceipts, r.row()); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return Receipt{}, refuse(ErrConflict, "Another receipt was appended to the chain meanwhile; retry.")
		}
		return Receipt{}, err
	}
	return r, nil
}

// Verification is the result of checking a receipt.
type Verification struct {
	Valid     bool
	Hash      bool // the stored hash is the hash of the fields as they are
	Signature bool // core's key signed the hash of the fields as they are
	Chain     bool // prev_hash is the hash of the previous receipt as it is
}

func (v Verification) view() map[string]any {
	return map[string]any{"valid": v.Valid, "checks": map[string]any{"hash": v.Hash, "signature": v.Signature, "chain": v.Chain}}
}

// VerifyReceipt recomputes a receipt's hash, checks its signature against core's keys (a key
// rotation keeps old receipts valid) and its link to the previous receipt, so a receipt edited in
// the database fails its own check and its successor's.
func (p *Plugin) VerifyReceipt(ctx context.Context, r Receipt) (Verification, error) {
	return p.s.verifyReceipt(ctx, r)
}

func (s *service) verifyReceipt(ctx context.Context, r Receipt) (Verification, error) {
	now := hashOf(r)
	v := Verification{Hash: equal(now, r.Hash)}
	if tok, err := s.codec.VerifyJWT(r.Signature, 0); err == nil && tok.Header("typ") == ReceiptJWTType {
		hash, _ := tok.Claim("receipt_hash").(string)
		seq, _ := tok.Claim("seq").(int64)
		v.Signature = equal(hash, now) && tok.Claim("receipt_id") == r.ID && tok.Claim("agent_id") == r.AgentID && seq == r.Seq
	}
	if r.Seq == 1 {
		v.Chain = r.PrevHash == ""
	} else {
		row, err := s.db.FindOne(ctx, TableReceipts, store.Criteria{"agent_id": r.AgentID, "seq": r.Seq - 1})
		if err != nil {
			return v, err
		}
		v.Chain = row != nil && r.PrevHash != "" && equal(hashOf(receiptFromRow(row)), r.PrevHash)
	}
	v.Valid = v.Hash && v.Signature && v.Chain
	return v, nil
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *service) receipt(ctx context.Context, id string) (Receipt, bool, error) {
	row, err := s.db.FindOne(ctx, TableReceipts, store.Criteria{"id": id})
	if err != nil || row == nil {
		return Receipt{}, false, err
	}
	return receiptFromRow(row), true, nil
}

func (s *service) lastReceipt(ctx context.Context, agentID string) (Receipt, bool, error) {
	rows, err := s.db.FindMany(ctx, TableReceipts, store.Criteria{"agent_id": agentID},
		store.Query{OrderBy: []store.Order{{Column: "seq", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return Receipt{}, false, err
	}
	return receiptFromRow(rows[0]), true, nil
}

// Receipts is the agent's chain from after (a seq) on, oldest first, at most limit (1 to 200)
// receipts: the export.
func (p *Plugin) Receipts(ctx context.Context, agentID string, after int64, limit int) ([]Receipt, error) {
	return p.s.receiptsOf(ctx, agentID, after, limit)
}

func (s *service) receiptsOf(ctx context.Context, agentID string, after int64, limit int) ([]Receipt, error) {
	limit = max(1, min(maxReceiptPage, limit))
	rows, err := s.db.FindMany(ctx, TableReceipts, store.Criteria{"agent_id": agentID, "seq": store.Gt(max(0, after))},
		store.Query{OrderBy: []store.Order{{Column: "seq"}}, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Receipt, 0, len(rows))
	for _, r := range rows {
		out = append(out, receiptFromRow(r))
	}
	return out, nil
}

// inputHash is the SHA-256 (hex) of the canonical JSON of the arguments: what a receipt keeps.
func inputHash(args map[string]any) string { return sha256Hex(canonicalJSON(args)) }

// hashOf is SHA-256 (hex) over the canonical JSON of the receipt's fields.
func hashOf(r Receipt) string { return sha256Hex(canonicalJSON(r.hashed())) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// canonicalJSON is upstream's canonical JSON: keys sorted at every level, slashes unescaped,
// non-ASCII as \uXXXX, an empty object as [] (PHP's json_encode of a sorted array).
func canonicalJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(emptyAsList(v)); err != nil {
		return fmt.Sprintf("%v", v) // unreachable for decoded JSON
	}
	raw := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		i += size
		switch {
		case r < utf8.RuneSelf:
			out = append(out, byte(r))
		case r < 0x10000:
			out = fmt.Appendf(out, `\u%04x`, r)
		default:
			r -= 0x10000
			out = fmt.Appendf(out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		}
	}
	return string(out)
}

func emptyAsList(v any) any {
	switch v := v.(type) {
	case map[string]any:
		if len(v) == 0 {
			return []any{}
		}
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = emptyAsList(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = emptyAsList(item)
		}
		return out
	}
	return v
}
