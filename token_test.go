// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"testing"
	"time"
	"unsafe"
)

func TestTokenExtra(t *testing.T) {
	type testCase struct {
		key  string
		val  any
		want any
	}
	const key = "extra-key"
	cases := []testCase{
		{key: key, val: "abc", want: "abc"},
		{key: key, val: 123, want: 123},
		{key: key, val: "", want: ""},
		{key: "other-key", val: "def", want: nil},
	}
	for _, tc := range cases {
		extra := make(map[string]any)
		extra[tc.key] = tc.val
		tok := &Token{raw: extra}
		if got, want := tok.Extra(key), tc.want; got != want {
			t.Errorf("Extra(%q) = %q; want %q", key, got, want)
		}
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Now()
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	cases := []struct {
		name string
		tok  *Token
		want bool
	}{
		{name: "12 seconds", tok: &Token{Expiry: now.Add(12 * time.Second)}, want: false},
		{name: "10 seconds", tok: &Token{Expiry: now.Add(defaultExpiryDelta)}, want: false},
		{name: "10 seconds-1ns", tok: &Token{Expiry: now.Add(defaultExpiryDelta - 1*time.Nanosecond)}, want: true},
		{name: "-1 hour", tok: &Token{Expiry: now.Add(-1 * time.Hour)}, want: true},
		{name: "12 seconds, custom expiryDelta", tok: &Token{Expiry: now.Add(12 * time.Second), expiryDelta: time.Second * 5}, want: false},
		{name: "5 seconds, custom expiryDelta", tok: &Token{Expiry: now.Add(time.Second * 5), expiryDelta: time.Second * 5}, want: false},
		{name: "5 seconds-1ns, custom expiryDelta", tok: &Token{Expiry: now.Add(time.Second*5 - 1*time.Nanosecond), expiryDelta: time.Second * 5}, want: true},
		{name: "-1 hour, custom expiryDelta", tok: &Token{Expiry: now.Add(-1 * time.Hour), expiryDelta: time.Second * 5}, want: true},
	}
	for _, tc := range cases {
		if got, want := tc.tok.expired(), tc.want; got != want {
			t.Errorf("expired (%q) = %v; want %v", tc.name, got, want)
		}
	}
}

// withWallClockJump returns a time whose monotonic reading is d beyond
// base's and whose wall-clock component is base's wall clock plus jump.
// It mirrors an NTP-style adjustment: the wall clock (the 33-bit seconds
// field of time.wall) is rewritten while the monotonic reading (time.ext)
// keeps advancing, which cannot be expressed through time's public API
// because time.Add always adjusts both representations together.
func withWallClockJump(base time.Time, d, jump time.Duration) time.Time {
	advanced := base.Add(d)
	const (
		hasMonotonicBit = 1 << 63
		nsecMask        = 1<<30 - 1
	)
	// Keep the hasMonotonic flag and the nanoseconds field; shift only the
	// 33-bit wall-seconds field by the whole-second part of jump.
	old := *(*uint64)(unsafe.Pointer(&advanced))
	secs := (old >> 30) & (1<<33 - 1)
	secs += uint64(int64(jump / time.Second))
	*(*uint64)(unsafe.Pointer(&advanced)) = hasMonotonicBit | (secs << 30) | (old & nsecMask)
	return advanced
}

// TestTokenExpiryMonotonicClockImmuneToWallJump verifies that a token
// retrieved in-process is judged against elapsed monotonic time, so moving
// the wall clock backwards (resurrecting an expired token) or forwards
// (killing a fresh token) cannot change the verdict.
func TestTokenExpiryMonotonicClockImmuneToWallJump(t *testing.T) {
	retrieved := time.Now()
	tok := &Token{
		AccessToken: "token",
		// 30s lifetime, anchored to the monotonic clock at retrieval.
		Expiry:      retrieved.Add(30 * time.Second),
		retrievedAt: retrieved,
	}

	// 40 monotonic seconds later: the token is genuinely expired.
	timeNow = func() time.Time { return withWallClockJump(retrieved, 40*time.Second, 0) }
	defer func() { timeNow = time.Now }()

	if !tok.expired() {
		t.Fatal("token expired by monotonic elapsed time; expired() = false")
	}

	// Wind the wall clock two hours backwards while the monotonic clock is
	// still only 40s past retrieval. A wall-clock-only comparison would have
	// resurrected this expired token; the monotonic verdict must not change.
	timeNow = func() time.Time { return withWallClockJump(retrieved, 40*time.Second, -2*time.Hour) }
	if !tok.expired() {
		t.Error("wall clock moved backwards resurrected an expired token")
	}

	// Conversely, a token only 5s into a 30s lifetime must stay valid even
	// if the wall clock jumps two hours forwards.
	fresh := &Token{
		AccessToken: "token",
		Expiry:      retrieved.Add(30 * time.Second),
		retrievedAt: retrieved,
	}
	timeNow = func() time.Time { return withWallClockJump(retrieved, 5*time.Second, 2*time.Hour) }
	if fresh.expired() {
		t.Error("wall clock moved forwards prematurely expired a fresh token")
	}
}

// TestTokenExpiryServerTimeOffset verifies that, once the monotonic anchor
// is lost, a server-derived offset corrects the expiry comparison for a
// skewed local clock instead of trusting the local wall clock blindly.
func TestTokenExpiryServerTimeOffset(t *testing.T) {
	// Simulate a token reconstructed without a monotonic anchor. The local
	// clock is one hour behind the server; the token expired on the server's
	// timeline 30s ago but still looks 59m30s valid locally.
	serverExpiry := time.Now().Round(0).Add(-30 * time.Second)
	tok := &Token{
		AccessToken:      "token",
		Expiry:           serverExpiry,
		serverTimeOffset: time.Hour,
		hasServerTime:    true,
	}
	timeNow = func() time.Time { return time.Now() }
	defer func() { timeNow = time.Now }()

	if !tok.expired() {
		t.Error("token expired on the server clock was judged valid using the skewed local clock")
	}
	if tok.WeakExpiry() {
		t.Error("token with a server time offset must not be reported as weak")
	}
}

// TestTokenWeakExpiry verifies that expiry falls back to the uncorrected
// local wall clock, and is explicitly flagged as weak, when neither a
// monotonic anchor nor a server time is available.
func TestTokenWeakExpiry(t *testing.T) {
	// A time built via time.Unix has no monotonic reading, mirroring a token
	// deserialized from JSON or constructed manually.
	expiry := time.Unix(time.Now().Add(time.Hour).Unix(), 0)
	tok := &Token{
		AccessToken: "token",
		Expiry:      expiry,
	}

	if !tok.WeakExpiry() {
		t.Error("token without monotonic anchor or server time should be weak")
	}
	if tok.expired() {
		t.Error("token expiring in an hour should be valid on the local clock")
	}

	// Recording retrieval metadata with a monotonic anchor makes it strong.
	retrieved := time.Now()
	tok.SetRetrievalMetadata(retrieved, 0, false)
	if tok.WeakExpiry() {
		t.Error("token with a monotonic anchor should not be weak")
	}
}

// TestTokenExpiryDeltaLongerThanLifetime checks the configured expiry delta
// still applies under the monotonic path: a delta exceeding the lifetime
// means a brand-new token is immediately treated as expired.
func TestTokenExpiryDeltaLongerThanLifetime(t *testing.T) {
	retrieved := time.Now()
	tok := &Token{
		AccessToken: "token",
		Expiry:      retrieved.Add(10 * time.Second),
		retrievedAt: retrieved,
		expiryDelta: time.Minute,
	}
	timeNow = func() time.Time { return retrieved }
	defer func() { timeNow = time.Now }()

	if !tok.expired() {
		t.Error("expiryDelta longer than the token lifetime should expire it immediately")
	}
}

// TestTokenJSONRoundTripDropsMonotonicAnchor verifies that serialization
// removes the process-local monotonic anchor and the unexported retrieval
// metadata (neither can be represented on the wire), so a deserialized token
// is always judged on the local wall clock and reported as weak.
func TestTokenJSONRoundTripDropsMonotonicAnchor(t *testing.T) {
	retrieved := time.Now()
	cases := []struct {
		name string
		tok  *Token
	}{
		{
			name: "server anchored",
			tok: &Token{
				AccessToken:      "token",
				Expiry:           retrieved.Add(time.Hour),
				retrievedAt:      retrieved,
				serverTimeOffset: 30 * time.Second,
				hasServerTime:    true,
			},
		},
		{
			name: "wall clock only",
			tok: &Token{
				AccessToken: "token",
				Expiry:      retrieved.Add(time.Hour),
				retrievedAt: retrieved,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.tok)
			if err != nil {
				t.Fatalf("Marshal = %v", err)
			}
			var got Token
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal = %v", err)
			}
			if !got.WeakExpiry() {
				t.Error("deserialized token without retrieval metadata must be weak")
			}
			// A token an hour from expiry must remain valid regardless of
			// which clock frame the decision is made in.
			if !got.Valid() {
				t.Error("token an hour from expiry should remain valid after round trip")
			}
		})
	}
}

func TestTokenTypeMethod(t *testing.T) {
	cases := []struct {
		name string
		tok  *Token
		want string
	}{
		{name: "bearer-mixed_case", tok: &Token{TokenType: "beAREr"}, want: "Bearer"},
		{name: "default-bearer", tok: &Token{}, want: "Bearer"},
		{name: "basic", tok: &Token{TokenType: "basic"}, want: "Basic"},
		{name: "basic-capitalized", tok: &Token{TokenType: "Basic"}, want: "Basic"},
		{name: "mac", tok: &Token{TokenType: "mac"}, want: "MAC"},
		{name: "mac-caps", tok: &Token{TokenType: "MAC"}, want: "MAC"},
		{name: "mac-mixed_case", tok: &Token{TokenType: "mAc"}, want: "MAC"},
	}
	for _, tc := range cases {
		if got, want := tc.tok.Type(), tc.want; got != want {
			t.Errorf("TokenType(%q) = %v; want %v", tc.name, got, want)
		}
	}
}
