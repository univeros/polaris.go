package scim

import (
	"encoding/json"
	"testing"
)

// FuzzPatch parses hostile PATCH bodies and reads every attribute the user and group patches
// read. Nothing may panic, and a refusal is always a SCIM error.
func FuzzPatch(f *testing.F) {
	for _, seed := range []string{
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","value":{"userName":"a@b.test","name":{"givenName":"A","familyName":"B"},"urn:ietf:params:scim:schemas:core:2.0:User:displayName":"X"}}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"u1\"]"},{"op":"add","path":"members","value":[{"value":"u2"},"u3"]}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add"},null,1]}`,
		`{"schemas":"x","Operations":{}}`,
	} {
		f.Add([]byte(seed))
	}
	attributes := []string{"active", "userName", "displayName", "name.formatted", "name.givenName", "name.familyName", "externalId"}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var body map[string]any
		if json.Unmarshal(raw, &body) != nil {
			return
		}
		ops, err := parsePatch(body)
		if err != nil {
			if _, ok := asError(err); !ok {
				t.Fatalf("not a SCIM error: %v", err)
			}
			return
		}
		for _, op := range ops {
			for _, a := range attributes {
				_ = op.scalar(a)
			}
			_, _ = memberIDs(op.value)
			_ = memberFilter.FindStringSubmatch(op.path)
		}
	})
}
