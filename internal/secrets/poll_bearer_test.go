// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testJWT(t *testing.T, sub string, aud interface{}, exp time.Time) string {
	t.Helper()
	claims, err := json.Marshal(map[string]interface{}{"sub": sub, "aud": aud, "exp": exp.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(claims) + ".sig"
}

func TestPollBearerRenewsOnlyNearExpiry(t *testing.T) {
	now := time.Now()
	fresh := testJWT(t, "owner", "privasys-platform", now.Add(15*time.Minute))
	asked := ""
	src := func(_ context.Context, aud string) (string, error) { asked = aud; return fresh, nil }
	ctx := WithBearerSource(context.Background(), src)

	long := testJWT(t, "owner", "privasys-platform", now.Add(10*time.Minute))
	if got := pollBearer(ctx, long); got != long || asked != "" {
		t.Errorf("a bearer with time left was replaced (asked %q)", asked)
	}
	short := testJWT(t, "owner", "privasys-platform", now.Add(30*time.Second))
	if got := pollBearer(ctx, short); got != fresh || asked != "privasys-platform" {
		t.Errorf("a bearer near its end was kept (asked %q)", asked)
	}
	list := testJWT(t, "owner", []string{"privasys-platform"}, now.Add(30*time.Second))
	if got := pollBearer(ctx, list); got != fresh {
		t.Error("a one-element aud list was not renewed")
	}
}

func TestPollBearerKeepsTheBearerItCannotReplaceSafely(t *testing.T) {
	now := time.Now()
	short := testJWT(t, "owner", "privasys-platform", now.Add(30*time.Second))
	cases := map[string]BearerSource{
		"source fails": func(context.Context, string) (string, error) { return "", errors.New("offline") },
		"another person": func(context.Context, string) (string, error) {
			return testJWT(t, "someone-else", "privasys-platform", now.Add(15*time.Minute)), nil
		},
		"another audience": func(context.Context, string) (string, error) {
			return testJWT(t, "owner", "vault", now.Add(15*time.Minute)), nil
		},
		"no later expiry": func(context.Context, string) (string, error) {
			return testJWT(t, "owner", "privasys-platform", now.Add(10*time.Second)), nil
		},
		"not a JWT": func(context.Context, string) (string, error) { return "opaque", nil },
	}
	for name, src := range cases {
		if got := pollBearer(WithBearerSource(context.Background(), src), short); got != short {
			t.Errorf("%s: the bearer was replaced", name)
		}
	}
	if got := pollBearer(context.Background(), short); got != short {
		t.Error("with no source the bearer was replaced")
	}
	if got := pollBearer(context.Background(), "opaque"); got != "opaque" {
		t.Error("an opaque bearer was replaced")
	}
}

// The case from the field: the card is tapped after the run's bearer expired.
func TestCollectBatchTokensPollsWithARenewedBearer(t *testing.T) {
	now := time.Now()
	stale := testJWT(t, "owner", "privasys-platform", now.Add(20*time.Second))
	fresh := testJWT(t, "owner", "privasys-platform", now.Add(15*time.Minute))
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		mu.Unlock()
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"status":"declined"}`))
	}))
	defer srv.Close()
	ctx := WithBearerSource(context.Background(), func(context.Context, string) (string, error) { return fresh, nil })
	b := &Batch{ID: "id", Exp: now.Unix() + 300}
	if _, err := CollectBatchTokens(ctx, srv.URL, stale, b); !errors.Is(err, ErrDeclined) {
		t.Fatalf("err = %v", err)
	}
	if len(seen) != 1 || seen[0] != fresh {
		t.Errorf("the poll did not use the renewed bearer")
	}
}
