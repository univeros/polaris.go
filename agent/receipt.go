package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// ReceiptType is the typ header of a receipt's signature.
const ReceiptType = "receipt+jwt"

// Receipt is one link of an agent's receipt chain, as GET /agents/{id}/receipts lists it.
type Receipt struct {
	ID           string  `json:"id"`
	AgentID      string  `json:"agent_id"`
	Seq          int     `json:"seq"`
	GrantID      *string `json:"grant_id"`
	Capability   *string `json:"capability"`
	InputHash    string  `json:"input_hash"`
	Outcome      string  `json:"outcome"`
	BudgetBefore *int    `json:"budget_before"`
	BudgetAfter  *int    `json:"budget_after"`
	PrevHash     *string `json:"prev_hash"`
	Hash         string  `json:"hash"`
	// Signature is a compact JWS (typ receipt+jwt) over the hash, signed with the server's key.
	Signature string `json:"signature"`
	// CreatedAt stays the server's text: it is hashed as sent.
	CreatedAt string `json:"created_at"`
}

// Verification is the verdict on a receipt, as GET /agents/receipts/{id}/verify gives it.
type Verification struct {
	Valid  bool   `json:"valid"`
	Checks Checks `json:"checks"`
}

// Checks are the three checks of a receipt: its hash, its signature, its link to the previous one.
type Checks struct {
	Hash      bool `json:"hash"`
	Signature bool `json:"signature"`
	Chain     bool `json:"chain"`
}

// hashedReceipt is the hashed fields, in sorted order, as the server's Receipt::hashed().
type hashedReceipt struct {
	AgentID      string  `json:"agent_id"`
	BudgetAfter  *int    `json:"budget_after"`
	BudgetBefore *int    `json:"budget_before"`
	Capability   *string `json:"capability"`
	CreatedAt    string  `json:"created_at"`
	GrantID      *string `json:"grant_id"`
	ID           string  `json:"id"`
	InputHash    string  `json:"input_hash"`
	Outcome      string  `json:"outcome"`
	PrevHash     *string `json:"prev_hash"`
	Seq          int     `json:"seq"`
}

// ReceiptHash is the SHA-256 (hex) of the receipt's canonical JSON, as the server computes it:
// keys sorted, slashes and <, >, & unescaped, non-ASCII as \uXXXX.
func ReceiptHash(r Receipt) string {
	data, err := marshalJSON(hashedReceipt{r.AgentID, r.BudgetAfter, r.BudgetBefore, r.Capability, r.CreatedAt, r.GrantID, r.ID, r.InputHash, r.Outcome, r.PrevHash, r.Seq})
	if err != nil {
		panic(fmt.Sprintf("agent: encode receipt: %v", err)) // strings, ints and nils always encode
	}
	sum := sha256.Sum256(asciiJSON(data))
	return hex.EncodeToString(sum[:])
}

// asciiJSON escapes every non-ASCII character of encoded JSON as \uXXXX (UTF-16 surrogate pairs
// above the BMP), lowercase hex.
func asciiJSON(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		i += size
		switch {
		case r < utf8.RuneSelf:
			out = append(out, byte(r)) //nolint:gosec // G115: r < utf8.RuneSelf, so it fits a byte
		case r < 0x10000:
			out = fmt.Appendf(out, `\u%04x`, r)
		default:
			r -= 0x10000
			out = fmt.Appendf(out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		}
	}
	return out
}

// VerifyReceipt does locally what GET /agents/receipts/{id}/verify does: the hash recomputed from
// the fields, the receipt+jwt signature verified with the server's keys (its JWKS) and bound to
// this receipt, and the link to previous (its recomputed hash is this receipt's prev_hash) when
// given. Without previous, a receipt after the first only needs a prev_hash.
func VerifyReceipt(r Receipt, keys []JWK, previous *Receipt) Verification {
	recomputed := ReceiptHash(r)
	hashOK := equal(recomputed, r.Hash)
	signatureOK := false
	if claims, err := verifyJWS(r.Signature, ReceiptType, keys); err == nil {
		h, _ := claims["receipt_hash"].(string)
		id, _ := claims["receipt_id"].(string)
		agent, _ := claims["agent_id"].(string)
		seq, _ := claims["seq"].(json.Number)
		signatureOK = equal(h, recomputed) && id == r.ID && agent == r.AgentID && seq.String() == fmt.Sprint(r.Seq)
	}
	var chainOK bool
	switch {
	case r.Seq == 1:
		chainOK = r.PrevHash == nil
	case previous == nil:
		chainOK = r.PrevHash != nil
	default:
		chainOK = previous.AgentID == r.AgentID && previous.Seq == r.Seq-1 && r.PrevHash != nil && equal(ReceiptHash(*previous), *r.PrevHash)
	}
	return Verification{Valid: hashOK && signatureOK && chainOK, Checks: Checks{Hash: hashOK, Signature: signatureOK, Chain: chainOK}}
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
