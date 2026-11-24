// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestRetrieveToken_InParams(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.FormValue("client_id"), clientID; got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}
		if got, want := r.FormValue("client_secret"), ""; got != want {
			t.Errorf("client_secret = %q; want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()
	_, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleInParams, styleCache)
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestRetrieveTokenWithContexts(t *testing.T) {
	styleCache := new(AuthStyleCache)
	const clientID = "client-id"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	}))
	defer ts.Close()

	_, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	if err != nil {
		t.Errorf("RetrieveToken (with background context) = %v; want no error", err)
	}

	retrieved := make(chan struct{})
	cancellingts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-retrieved
	}))
	defer cancellingts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RetrieveToken(ctx, clientID, "", cancellingts.URL, url.Values{}, AuthStyleUnknown, styleCache)
	close(retrieved)
	if err == nil {
		t.Errorf("RetrieveToken (with cancelled context) = nil; want error")
	}
}

func TestExpiresInUpperBound(t *testing.T) {
	var e expirationTime
	if err := e.UnmarshalJSON([]byte(fmt.Sprint(int64(math.MaxInt32) + 1))); err != nil {
		t.Fatal(err)
	}
	const want = math.MaxInt32
	if e != want {
		t.Errorf("expiration time = %v; want %v", e, want)
	}
}

func TestAuthStyleCache(t *testing.T) {
	var c LazyAuthStyleCache

	cases := []struct {
		url      string
		clientID string
		style    AuthStyle
	}{
		{
			"https://host1.example.com/token",
			"client_1",
			AuthStyleInHeader,
		}, {
			"https://host2.example.com/token",
			"client_2",
			AuthStyleInParams,
		}, {
			"https://host1.example.com/token",
			"client_3",
			AuthStyleInParams,
		},
	}

	for _, tt := range cases {
		t.Run(tt.clientID, func(t *testing.T) {
			cc := c.Get()
			got, ok := cc.lookupAuthStyle(tt.url, tt.clientID)
			if ok {
				t.Fatalf("unexpected auth style found on first request: %v", got)
			}

			cc.setAuthStyle(tt.url, tt.clientID, tt.style)

			got, ok = cc.lookupAuthStyle(tt.url, tt.clientID)
			if !ok {
				t.Fatalf("auth style not found in cache")
			}

			if got != tt.style {
				t.Fatalf("auth style mismatch, got=%v, want=%v", got, tt.style)
			}
		})
	}
}

func TestServerTimeOffset(t *testing.T) {
	local := time.Now().UTC()
	server := local.Add(5 * time.Minute)
	h := http.Header{}
	h.Set("Date", server.Format(http.TimeFormat))

	offset, ok := serverTimeOffset(h, local)
	if !ok {
		t.Fatal("serverTimeOffset reported no usable Date header")
	}
	// HTTP dates carry only second precision, so allow a one-second window.
	if got := offset; got < 5*time.Minute-time.Second || got > 5*time.Minute+time.Second {
		t.Errorf("offset = %v; want roughly %v", got, 5*time.Minute)
	}

	if _, ok := serverTimeOffset(http.Header{}, local); ok {
		t.Error("missing Date header should report ok=false")
	}

	bad := http.Header{}
	bad.Set("Date", "not a date")
	if _, ok := serverTimeOffset(bad, local); ok {
		t.Error("unparseable Date header should report ok=false")
	}
}

func TestRetrieveTokenClockMetadata(t *testing.T) {
	const clientID = "client-id"

	t.Run("with server date", func(t *testing.T) {
		serverNow := time.Now().Add(time.Hour).UTC()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Date", serverNow.Format(http.TimeFormat))
			io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer", "expires_in": 3600}`)
		}))
		defer ts.Close()

		tok, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleInParams, new(AuthStyleCache))
		if err != nil {
			t.Fatalf("RetrieveToken = %v", err)
		}
		if tok.RetrievedAt == tok.RetrievedAt.Round(0) {
			t.Error("RetrievedAt should carry a monotonic clock reading")
		}
		if tok.WeakExpiry {
			t.Error("a token endpoint returning a Date should not produce a weak expiry")
		}
		if got := tok.ServerTimeOffset.Truncate(time.Second); got < time.Hour-time.Second || got > time.Hour+time.Second {
			t.Errorf("ServerTimeOffset = %v; want roughly %v", got, time.Hour)
		}
		if tok.Expiry.IsZero() || !tok.Expiry.After(tok.RetrievedAt) {
			t.Errorf("Expiry = %v should be after RetrievedAt = %v", tok.Expiry, tok.RetrievedAt)
		}
	})

	t.Run("without server date", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hijack and write a raw response so net/http does not inject
			// its default Date header, exercising the weak-expiry path.
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatalf("Hijack = %v", err)
			}
			defer conn.Close()
			fmt.Fprint(brw, "HTTP/1.1 200 OK\r\n")
			fmt.Fprint(brw, "Content-Type: application/json\r\n")
			fmt.Fprint(brw, "Content-Length: 76\r\n\r\n")
			fmt.Fprint(brw, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer", "expires_in": 3600}`)
			brw.Flush()
		}))
		defer ts.Close()

		tok, err := RetrieveToken(context.Background(), clientID, "", ts.URL, url.Values{}, AuthStyleInParams, new(AuthStyleCache))
		if err != nil {
			t.Fatalf("RetrieveToken = %v", err)
		}
		if !tok.WeakExpiry {
			t.Error("a token endpoint without a Date should produce a weak expiry")
		}
		if tok.ServerTimeOffset != 0 {
			t.Errorf("ServerTimeOffset = %v; want zero without a Date", tok.ServerTimeOffset)
		}
		if tok.RetrievedAt == tok.RetrievedAt.Round(0) {
			t.Error("RetrievedAt should still carry a monotonic clock reading")
		}
	})
}
