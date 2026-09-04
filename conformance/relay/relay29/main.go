// Command relay29-harness runs a pinned fiatjaf/relay29 (khatru29) NIP-29
// relay for OmaChat's black-box interoperability job.
//
// It is a test fixture, not a deployment: state is in memory, the relay key
// comes from RELAY29_SECRET so the probe can predict the signing identity,
// and the moderation policy is the smallest one that exercises every action
// OmaChat's reducers model (create, metadata edit, put-user, remove-user,
// delete-event, join and leave requests).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/fiatjaf/khatru/policies"
	"github.com/fiatjaf/relay29"
	"github.com/fiatjaf/relay29/khatru29"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip29"
)

var (
	adminRole     = &nip29.Role{Name: "admin", Description: "group owner"}
	moderatorRole = &nip29.Role{Name: "moderator", Description: "removes people and messages"}
)

func main() {
	port := os.Getenv("RELAY29_PORT")
	if port == "" {
		port = "2929"
	}
	secret := os.Getenv("RELAY29_SECRET")
	if secret == "" {
		secret = nostr.GeneratePrivateKey()
	}
	domain := os.Getenv("RELAY29_DOMAIN")
	if domain == "" {
		domain = "127.0.0.1:" + port
	}

	db := &slicestore.SliceStore{}
	if err := db.Init(); err != nil {
		log.Fatalf("init store: %v", err)
	}

	relay, state := khatru29.Init(relay29.Options{
		Domain:                  domain,
		DB:                      db,
		SecretKey:               secret,
		DefaultRoles:            []*nip29.Role{adminRole, moderatorRole},
		GroupCreatorDefaultRole: adminRole,
	})
	relayPubkey, err := nostr.GetPublicKey(secret)
	if err != nil {
		log.Fatalf("derive relay public key: %v", err)
	}

	state.AllowAction = func(ctx context.Context, group nip29.Group, role *nip29.Role, action relay29.Action) bool {
		if role == adminRole {
			return true
		}
		if role == moderatorRole {
			switch action.(type) {
			case relay29.PutUser, relay29.RemoveUser, relay29.DeleteEvent:
				return true
			}
		}
		return false
	}

	relay.Info.Name = "OmaChat NIP-29 interoperability harness"
	relay.Info.Description = "pinned relay29 fixture; in-memory state"
	relay.RejectEvent = append(relay.RejectEvent,
		policies.PreventLargeTags(64),
		policies.PreventTooManyIndexableTags(6, []int{9005}, nil),
		policies.RestrictToSpecifiedKinds(true,
			9, 10, 11, 12,
			9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007,
			9021, 9022,
		),
		policies.PreventTimestampsInThePast(60*time.Second),
		policies.PreventTimestampsInTheFuture(30*time.Second),
	)

	relay.Router().HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OmaChat NIP-29 harness: connect with a Nostr client")
	})

	fmt.Printf("relay29 harness listening on http://127.0.0.1:%s\n", port)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "application/nostr+json") {
			document, err := json.Marshal(relay.Info)
			if err != nil {
				http.Error(w, "could not encode relay information", http.StatusInternalServerError)
				return
			}
			var fields map[string]any
			if err := json.Unmarshal(document, &fields); err != nil {
				http.Error(w, "could not prepare relay information", http.StatusInternalServerError)
				return
			}
			fields["self"] = relayPubkey
			w.Header().Set("Content-Type", "application/nostr+json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if err := json.NewEncoder(w).Encode(fields); err != nil {
				log.Printf("encode relay information: %v", err)
			}
			return
		}
		relay.ServeHTTP(w, r)
	})
	if err := http.ListenAndServe("127.0.0.1:"+port, handler); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
