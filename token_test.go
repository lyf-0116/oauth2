// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/url"
	"testing"
	"time"
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

func TestMergeRefreshedToken(t *testing.T) {
	oldExpiry := time.Unix(123456789, 0)
	newExpiry := time.Unix(987654321, 0)

	tests := []struct {
		name     string
		response *Token
		want     *Token
	}{
		{
			name: "missing refresh token is preserved",
			response: &Token{
				AccessToken: "new-access",
				TokenType:   "bearer",
				ExpiresIn:   3600,
				Expiry:      newExpiry,
				raw: map[string]any{
					"access_token": "new-access",
					"token_type":   "bearer",
					"expires_in":   float64(3600),
				},
			},
			want: &Token{
				AccessToken:  "new-access",
				TokenType:    "bearer",
				RefreshToken: "old-refresh",
				ExpiresIn:    3600,
				Expiry:       newExpiry,
			},
		},
		{
			name: "missing access token preserves access state",
			response: &Token{
				RefreshToken: "new-refresh",
				raw:          map[string]any{"refresh_token": "new-refresh"},
			},
			want: &Token{
				AccessToken:  "old-access",
				TokenType:    "mac",
				RefreshToken: "new-refresh",
				ExpiresIn:    60,
				Expiry:       oldExpiry,
			},
		},
		{
			name: "explicit empty refresh token clears",
			response: &Token{
				raw: map[string]any{"refresh_token": ""},
			},
			want: &Token{
				AccessToken:  "old-access",
				TokenType:    "mac",
				RefreshToken: "",
				ExpiresIn:    60,
				Expiry:       oldExpiry,
			},
		},
		{
			name: "explicit null refresh token clears",
			response: &Token{
				raw: map[string]any{"refresh_token": nil},
			},
			want: &Token{
				AccessToken: "old-access",
				TokenType:   "mac",
				ExpiresIn:   60,
				Expiry:      oldExpiry,
			},
		},
		{
			name: "explicit empty form refresh token clears",
			response: &Token{
				raw: url.Values{"refresh_token": {""}},
			},
			want: &Token{
				AccessToken: "old-access",
				TokenType:   "mac",
				ExpiresIn:   60,
				Expiry:      oldExpiry,
			},
		},
		{
			name: "new access token without expiry resets old expiry and type",
			response: &Token{
				AccessToken: "new-access",
				raw:         map[string]any{"access_token": "new-access"},
			},
			want: &Token{
				AccessToken:  "new-access",
				RefreshToken: "old-refresh",
			},
		},
		{
			name: "explicit empty expiry clears expiry",
			response: &Token{
				AccessToken: "new-access",
				raw: map[string]any{
					"access_token": "new-access",
					"expires_in":   nil,
				},
			},
			want: &Token{
				AccessToken:  "new-access",
				RefreshToken: "old-refresh",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := &Token{
				AccessToken:  "old-access",
				TokenType:    "mac",
				RefreshToken: "old-refresh",
				ExpiresIn:    60,
				Expiry:       oldExpiry,
			}
			got := mergeRefreshedToken(current, tt.response)
			if got.AccessToken != tt.want.AccessToken ||
				got.TokenType != tt.want.TokenType ||
				got.RefreshToken != tt.want.RefreshToken ||
				got.ExpiresIn != tt.want.ExpiresIn ||
				!got.Expiry.Equal(tt.want.Expiry) {
				t.Errorf("mergeRefreshedToken() = %#v; want %#v", got, tt.want)
			}
			if current.RefreshToken != "old-refresh" {
				t.Errorf("current token mutated: RefreshToken = %q; want old-refresh", current.RefreshToken)
			}
		})
	}
}
