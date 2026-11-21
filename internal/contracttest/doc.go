// Package contracttest replays the upstream contract fixtures against a Go http.Handler.
//
// Each upstream PHP functional test recorded its request/response steps as
// upstream/fixtures/<package>/<PHP test name, dotted>.json. The Go port of that test issues the
// same requests through a Client; every response is normalized (volatile headers dropped,
// header names lower-cased, tokens, ids, codes and timestamps masked, record lists compared as
// sets, JSON bodies compared structurally) and compared with the recorded step:
//
//	func TestLoginEndpoint(t *testing.T) {
//		dir := contracttest.Fixtures(t, "core")
//		t.Run("testLoginReturnsTokens", func(t *testing.T) {
//			fx := contracttest.For(t, dir, `Polaris\Tests\Functional\LoginEndpointTest`, "testLoginReturnsTokens")
//			c := contracttest.NewClient(t, newServer(t), fx)
//			resp := c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": pw})
//			...
//		}) // the test fails if a recorded step was not replayed
//	}
//
// A package proves every fixture has a Go test with Uncovered. The environment the fixtures were
// recorded in (APP_KEY, issuer, keys, clocks, rate limits) is documented and exported in env.go.
package contracttest
