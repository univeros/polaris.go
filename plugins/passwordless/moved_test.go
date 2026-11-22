package passwordless

import "testing"

// Decision 74. A code is for the address it was sent to: once the account has moved to another
// one (a directory renamed it), the old mailbox's codes neither reset its password nor verify it.
func TestACodeSentToAnAddressDiesWhenTheAccountLeavesIt(t *testing.T) {
	e := boot(t, Config{})
	u := e.user("ada@example.com", true)
	ok(t, e.v.sendEmailCode(e.ctx, "ada@example.com", PurposeResetPassword))
	code := e.mailCode()
	if _, err := e.g.Identity().ChangeEmail(e.ctx, u.ID, "ada@elsewhere.example", false); err != nil {
		t.Fatal(err)
	}
	ok(t, e.v.sendEmailCode(e.ctx, "ada@elsewhere.example", PurposeVerifyEmail))
	verification := e.mailCode()
	if _, err := e.g.Identity().ChangeEmail(e.ctx, u.ID, "ada@third.example", false); err != nil {
		t.Fatal(err)
	}

	refused(t, e.v.resetPassword(e.ctx, "ada@example.com", code, "a brand new passphrase"), ErrCodeInvalid, "a reset code of the address the account left")
	refused(t, e.v.verifyEmail(e.ctx, "ada@elsewhere.example", verification), ErrCodeInvalid, "a verification code of the address the account left")
	got := e.reload(u.ID)
	if got.EmailVerifiedAt != nil || !e.g.Hasher().Verify(tPass, *got.PasswordHash) {
		t.Fatalf("the old mailbox changed the account: %+v", got)
	}
}
