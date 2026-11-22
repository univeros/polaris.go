package mfa

import (
	"log/slog"
	"strconv"
)

// ConfirmResult is the outcome of confirming a factor. RecoveryCodes is non-empty only when the
// confirmation activated the user's first factor: the codes are shown this once, only their
// hashes are stored. It keeps the codes out of fmt and slog output.
type ConfirmResult struct {
	RecoveryCodes []string
}

func (r ConfirmResult) String() string {
	return "mfa.ConfirmResult{" + strconv.Itoa(len(r.RecoveryCodes)) + " recovery codes}"
}

// GoString keeps the recovery codes out of %#v output.
func (r ConfirmResult) GoString() string { return r.String() }

// LogValue keeps the recovery codes out of logs.
func (r ConfirmResult) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("recovery_codes", len(r.RecoveryCodes)))
}
