package anonymous_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/anonymous"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// A visitor signs in as a guest; once they have a real account, POST /anonymous/convert hands both
// ids to OnConvert, where the host moves what it kept under the guest.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	db := memstore.New(append(schema.Core(), anonymous.Models()...)...) // sqlstore.Open(...) in production

	guests := anonymous.New(anonymous.Config{
		OnConvert: func(ctx context.Context, guestID, userID string) error {
			return nil // e.g. carts.Reassign(ctx, guestID, userID)
		},
	})
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      db,
		Plugins: []polaris.Plugin{guests},
	})
	if err != nil {
		log.Fatal(err)
	}

	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/anonymous/sign-in", nil))
	var body struct {
		Data struct {
			User struct{ Email string } `json:"user"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	fmt.Println(w.Code, strings.HasSuffix(body.Data.User.Email, "@anonymous.invalid"))

	pruned, _ := guests.Prune(context.Background()) // from cron: unconverted guests older than 30 days
	fmt.Println(pruned)
	// Output:
	// 201 true
	// 0
}
