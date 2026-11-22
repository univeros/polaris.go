package oauth_test

import (
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
)

// Every oauth-provider fixture has a Go test that replays it.
func TestEveryFixtureIsReplayed(t *testing.T) {
	covered := []string{
		flowFixtures + "::testAuthorizationCodeWithPkceConsentRefreshRotationAndRevocation",
		flowFixtures + "::testACodePresentedTwiceRevokesTheTokensItIssued",
		flowFixtures + "::testClientCredentialsDeviceFlowBackchannelAndTokenExchange",
		flowFixtures + "::testDpopBindsTokensToTheClientsKeyAndRefusesAReplayedProof",
		flowFixtures + "::testDiscoveryTrustedClientsMetadataDocumentsAndAdministration",
		registrationFixtures + "::testAnyoneRegistersAClientAndAKeyedClientAuthenticatesWithAnAssertion",
	}
	missing, err := contracttest.Uncovered(contracttest.Fixtures(t, "oauth-provider"), covered)
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
