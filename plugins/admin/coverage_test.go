package admin_test

import (
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
)

// Every admin fixture has a Go test that replays it (newFlow in the functional tests).
func TestEveryFixtureIsReplayed(t *testing.T) {
	covered := []string{
		fixturePrefix + "AdminUsersTest::testAnOwnerManagesUsersAndEveryActionIsAudited",
		fixturePrefix + "AdminUsersTest::testASuperadminIsAnOwnerWithoutAGrantAndCannotBeImpersonated",
		fixturePrefix + "AdminUsersTest::testAViewerKeyReadsAndCannotMutateAndADeletedKeyIsRefused",
		fixturePrefix + "AdminKeysGrantsAndStatsTest::testKeysAndGrantsAreOwnerOnlyAndAudited",
		fixturePrefix + "AdminKeysGrantsAndStatsTest::testAnOrganizationOwnerCreatesKeysAndGrantsForTheirOrganizationOnly",
		fixturePrefix + "AdminKeysGrantsAndStatsTest::testStatsCountTheInstance",
		fixturePrefix + "AdminOrganizationsTest::testOrganizationsAreListedReadRolesSetAndDeleted",
		fixturePrefix + "AdminOrganizationsTest::testAnOrganizationScopedPrincipalSeesItsOrganizationOnly",
		fixturePrefix + "AdminOrganizationsTest::testDrainsAreManagedPerOrganizationByOwners",
		fixturePrefix + "AdminSessionsAndMfaTest::testSessionsAreListedAndRevokedBySupport",
		fixturePrefix + "AdminSessionsAndMfaTest::testMfaFactorsAreListedRemovedAndReset",
	}
	missing, err := contracttest.Uncovered(contracttest.Fixtures(t, "admin"), covered)
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
