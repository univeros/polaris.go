package contracttest

// knownChanges are the recorded 1.0 responses the extraction deliberately changed, ported
// verbatim from tests/Contract/KnownChanges.php (each documented upstream in
// docs/extraction/behaviour-changes.md). The key is the PHP test name, the step is 1-based, and
// the value is the expected response already normalized: the replay compares against it instead
// of the recording.
var knownChanges = map[string]map[int]normalized{
	`Polaris\Tests\Functional\MfaLoginGateEndpointsTest::testTheTicketPrincipalCannotBeSpoofedViaTheBody`: {
		7: {
			Status:  422,
			Headers: map[string][]string{"content-type": {"application/json"}, "x-ratelimit-limit": {"10"}},
			Body:    map[string]any{"error": "invalid_code", "message": "The verification code is invalid."},
		},
	},
}

// knownHeaders are headers Go adds, deliberately, to recorded responses: the replay expects the
// recording's headers plus these (already normalized) on the 1-based step, everything else
// compared as recorded. Each is a decision in docs/port/decisions.md.
var knownHeaders = map[string]map[int]map[string][]string{}
