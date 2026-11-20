package oauth_test

import (
	"testing"

	"github.com/univeros/polaris-go/internal/contracttest"
)

// Every oauth-provider fixture has a Go test (port of ContractCoverageTest).
func TestEveryFixtureIsReplayed(t *testing.T) {
	covered := []string{
		phpFlow + "::testAuthorizationCodeWithPkceConsentRefreshRotationAndRevocation",
		phpFlow + "::testACodePresentedTwiceRevokesTheTokensItIssued",
		phpFlow + "::testClientCredentialsDeviceFlowBackchannelAndTokenExchange",
		phpFlow + "::testDpopBindsTokensToTheClientsKeyAndRefusesAReplayedProof",
		phpFlow + "::testDiscoveryTrustedClientsMetadataDocumentsAndAdministration",
		phpRegister + "::testAnyoneRegistersAClientAndAKeyedClientAuthenticatesWithAnAssertion",
	}
	missing, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "oauth-provider"), covered)
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
